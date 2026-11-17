//! Mach-O (arm64, MH_EXECUTE) 只读解析。
//!
//! 目的是在没有源码、没有调试符号的前提下，仅凭二进制自身的信息完成：
//!   1. 枚举出所有节区及其文件偏移/虚拟地址；
//!   2. 通过 dysymtab 的间接符号表，把 `__stubs` 里每个 stub 解析成导入函数名
//!      （_recvfrom 等），从而确定“调用点签名”要匹配的目标；
//!   3. 找到可用于注入的 code cave（专用 __patchcave 节，或全 0 对齐空洞）；
//!   4. 收集已定义符号，作为函数级定位的辅助手段。
//!
//! 全程只读文件、不执行目标程序。

use object::macho;
use object::read::macho::MachOFile;
use object::{Endianness, ReadRef, SymbolIndex};
use std::path::Path;

/// 一个节区的静态描述。
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub segment: String,
    pub vm_addr: u64,
    pub size: u64,
    pub file_off: u64,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        // S_ATTR_PURE_INSTRUCTIONS(0x80000000) | S_ATTR_SOME_INSTRUCTIONS(0x400)
        self.flags & (0x8000_0000 | 0x0000_0400) != 0
    }

    pub fn section_type(&self) -> u8 {
        (self.flags & 0xff) as u8
    }

    pub fn is_symbol_stubs(&self) -> bool {
        self.section_type() == macho::S_SYMBOL_STUBS.0
    }
}

/// 一个符号 stub 的入口地址和它绑定的导入符号名。
#[derive(Debug, Clone)]
pub struct Stub {
    pub vm_addr: u64,
    /// 单个 stub 的字节数（解析间接符号表时使用，作为结构元数据保留）。
    #[allow(dead_code)]
    pub size: u64,
    pub symbol: String,
}

#[derive(Debug)]
pub struct MachOInfo {
    pub sections: Vec<Section>,
    pub stubs: Vec<Stub>,
    /// 已定义符号（名字 -> 虚拟地址），用于函数名辅助定位。
    pub defined_symbols: Vec<(String, u64)>,
    pub entry: u64,
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ParseError {}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// <mach-o/nlist.h>：间接符号表项的特殊标记。
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

pub fn parse(path: &Path) -> Result<MachOInfo, ParseError> {
    let data = std::fs::read(path)
        .map_err(|e| ParseError(format!("读取 {} 失败: {e}", path.display())))?;
    parse_bytes(&data)
}

pub fn parse_bytes(data: &[u8]) -> Result<MachOInfo, ParseError> {
    type Header = macho::MachHeader64<Endianness>;
    let obj = MachOFile::<Header>::parse(data)
        .map_err(|e| ParseError(format!("不是合法的 64 位 Mach-O: {e}")))?;

    let endian = obj.endian();
    let header = obj.macho_header();
    if header.cputype.get(endian) != macho::CPU_TYPE_ARM64 {
        return Err(ParseError(format!(
            "本工具只支持 arm64 Mach-O，cputype={}",
            header.cputype.get(endian)
        )));
    }
    if header.filetype.get(endian) != macho::MH_EXECUTE {
        return Err(ParseError(format!(
            "只支持 MH_EXECUTE 可执行文件，filetype={:?}",
            header.filetype.get(endian)
        )));
    }

    let mut sections: Vec<Section> = Vec::new();
    let mut dysym: Option<&macho::DysymtabCommand<Endianness>> = None;
    let mut entryoff: Option<u64> = None;
    let mut text_vmaddr: Option<u64> = None;

    let commands = obj
        .macho_load_commands()
        .map_err(|e| ParseError(format!("遍历 load command 失败: {e}")))?;
    for cmd in commands {
        let cmd = cmd.map_err(|e| ParseError(format!("解析 load command 失败: {e}")))?;
        let variant = cmd
            .variant()
            .map_err(|e| ParseError(format!("解析 load command 变体失败: {e}")))?;
        match variant {
            object::read::macho::LoadCommandVariant::Segment64(seg, section_data) => {
                let segname = cstr(&seg.segname);
                if segname == "__TEXT" {
                    text_vmaddr = Some(seg.vmaddr.get(endian));
                }
                let nsects = seg.nsects.get(endian) as usize;
                let raw: &[macho::Section64<Endianness>] = section_data
                    .read_slice_at(0, nsects)
                    .map_err(|_| ParseError("解析 __TEXT 节区表失败".into()))?;
                for sect in raw {
                    sections.push(Section {
                        name: cstr(&sect.sectname),
                        segment: segname.clone(),
                        vm_addr: sect.addr.get(endian),
                        size: sect.size.get(endian),
                        file_off: sect.offset.get(endian) as u64,
                        flags: sect.flags.get(endian).0,
                        reserved1: sect.reserved1.get(endian),
                        reserved2: sect.reserved2.get(endian),
                    });
                }
            }
            object::read::macho::LoadCommandVariant::Dysymtab(d) => {
                dysym = Some(d);
            }
            object::read::macho::LoadCommandVariant::EntryPoint(ep) => {
                // LC_MAIN 可能先于 LC_SEGMENT 出现，先记下偏移，循环后再换算。
                entryoff = Some(ep.entryoff.get(endian));
            }
            _ => {}
        }
    }

    // MH_EXECUTE 的 __TEXT 段 vmaddr 即链接基址（固定链接，slide=0 视角）。
    let text_base = text_vmaddr.ok_or_else(|| ParseError("缺少 __TEXT 段".into()))?;
    let entry = text_base + entryoff.unwrap_or(0);

    // ---- 间接符号表：stub 入口 -> 导入名 ----
    let mut stubs: Vec<Stub> = Vec::new();
    let symtab = obj.macho_symbol_table();
    if let Some(d) = dysym {
        let indirect = d
            .indirect_symbols(endian, data)
            .map_err(|e| ParseError(format!("读取间接符号表失败: {e}")))?;
        for sec in &sections {
            if !sec.is_symbol_stubs() {
                continue;
            }
            let stub_size = sec.reserved2.max(4) as u64;
            let count = sec.size / stub_size;
            for i in 0..count {
                let idx32 = indirect[(sec.reserved1 as usize) + i as usize]
                    .get(endian)
                    .0;
                if idx32 & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let nlist = match symtab.symbol(SymbolIndex(idx32 as usize)) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let name = match symtab.symbol_name(endian, nlist) {
                    Ok(n) => cstr(n),
                    Err(_) => continue,
                };
                stubs.push(Stub {
                    vm_addr: sec.vm_addr + i * stub_size,
                    size: stub_size,
                    symbol: name,
                });
            }
        }
    }

    // ---- 已定义符号（剥离过的二进制这里可能为空，属正常）----
    let mut defined_symbols = Vec::new();
    for (_idx, nlist) in symtab.enumerate() {
        let flags = nlist.n_type;
        if flags.is_stab() {
            continue;
        }
        if flags.typ() == macho::N_UNDF {
            continue; // 导入符号
        }
        if let Ok(name) = symtab.symbol_name(endian, nlist) {
            let nm = cstr(name);
            if !nm.is_empty() {
                defined_symbols.push((nm, nlist.n_value.get(endian)));
            }
        }
    }

    Ok(MachOInfo {
        sections,
        stubs,
        defined_symbols,
        entry,
    })
}

impl MachOInfo {
    /// 按导入符号名找 stub（如 "_recvfrom"）。
    pub fn stub_by_name(&self, name: &str) -> Option<&Stub> {
        self.stubs.iter().find(|s| s.symbol == name)
    }

    pub fn section_by_name(&self, segment: &str, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.segment == segment && s.name == name)
    }

    /// 找到包含某虚拟地址的节区。
    #[allow(dead_code)] // 通用地址翻译辅助，库 API 保留
    pub fn section_of(&self, vm_addr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| vm_addr >= s.vm_addr && vm_addr < s.vm_addr.saturating_add(s.size))
    }

    /// 虚拟地址 -> 文件偏移（只在有文件映射的节区有效）。
    pub fn vm_to_file(&self, vm_addr: u64) -> Option<u64> {
        self.sections.iter().find_map(|s| {
            if vm_addr >= s.vm_addr && vm_addr < s.vm_addr.saturating_add(s.size) {
                Some(s.file_off + (vm_addr - s.vm_addr))
            } else {
                None
            }
        })
    }

    /// 找函数符号（带不带前导下划线都接受）。
    #[allow(dead_code)] // 与 symbol_containing 配套的按名查询 API，CLI 之外可复用
    pub fn symbol_addr(&self, name: &str) -> Option<u64> {
        let want = name.trim_start_matches('_');
        self.defined_symbols
            .iter()
            .find(|(n, _)| n.trim_start_matches('_') == want)
            .map(|(_, a)| *a)
    }

    /// 返回地址不超过 `addr` 的最近一个已定义符号（用于标注某地址所属函数）。
    /// 剥离过符号的二进制返回 None。
    pub fn symbol_containing(&self, addr: u64) -> Option<(&str, u64)> {
        self.defined_symbols
            .iter()
            .filter(|(_, a)| *a <= addr)
            .max_by_key(|(_, a)| *a)
            .map(|(n, a)| (n.as_str(), *a))
    }
}
