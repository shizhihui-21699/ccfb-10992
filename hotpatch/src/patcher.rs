//! 核心热补丁逻辑：无源码定位缺陷点、生成 code cave 桩、改写跳转。
//!
//! 稳妥性设计（为什么这样插）：
//!   * 不移动任何原有节区、不改 load command、不改文件大小 —— 所有代码签名之外的
//!     结构偏移保持不变，dyld 绑定、Objective-C 元数据等都不受影响；
//!   * 只写两处：可执行节区内部的一个空闲洞穴（code cave），以及缺陷点的一条
//!     指令（4 字节，原地改成 B）。不改动的指令一个字节都不碰；
//!   * 补丁桩只使用调用者易失寄存器 x16/x17（AAPCS64 的 IP0/IP1），并在桩内
//!     自行恢复被替换指令的副作用（x2 = 原始长度），返回后程序的寄存器状态与
//!     原执行流完全一致；
//!   * 长度检查是“钳制”而非拒绝：recvfrom 收到的实际字节数被限制在缓冲区容量
//!     内，语义上等价于“先检查长度、超长部分不收”，其余业务逻辑零改动。

use crate::arm64;
use crate::macho_info::{MachOInfo, Section};

/// 补丁状态标记（写在洞穴头部，便于 verify / 防重复打补丁）。
pub const MAGIC: [u8; 4] = *b"HPC1";

/// 补丁桩的固定布局（单位：字节，洞穴内偏移）。
///   0..4    magic "HPC1"
///   4..8    原始被替换指令字 (u32)
///   8..12   钳制上限 cap (u32)
///   12..20  钩子虚拟地址 hook_vm (u64)
///   20..28  recvfrom stub 虚拟地址 (u64)
///   28..36  返回到的虚拟地址（hook_vm + 4）(u64)
///   36..44  洞穴代码起始虚拟地址（= cave_vm + CODE_OFF）(u64)
pub const META_SIZE: usize = 44;
pub const CODE_OFF: usize = META_SIZE;

#[derive(Debug)]
pub struct PatchError(pub String);

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PatchError {}

/// 定位到的缺陷点。
#[derive(Debug, Clone)]
pub struct BugSite {
    /// 被替换指令（mov xN, #oversized）的虚拟地址。
    pub hook_vm: u64,
    /// 被替换指令的原始指令字。
    pub original_word: u32,
    /// 该 mov 装载的长度立即数（即失控的 recvfrom 长度参数）。
    pub oversized_len: u16,
    /// 目标寄存器（recvfrom 的长度参数寄存器，应为 x2）。
    pub len_reg: u8,
    /// recvfrom stub 的虚拟地址。
    pub recvfrom_stub_vm: u64,
}

/// 一次成功补丁的完整信息（用于报告与 verify）。
#[derive(Debug, Clone)]
pub struct PatchPlan {
    pub site: BugSite,
    pub cave_vm: u64,
    pub cave_file_off: u64,
    pub cave_size: u64,
    pub cap: u16,
    pub stub_words: Vec<u32>,
}

/// BL 指令解码：返回（是否为 BL, 目标绝对地址）。
fn decode_bl(word: u32, pc: u64) -> (bool, u64) {
    if word & 0xfc00_0000 != 0x9400_0000 {
        return (false, 0);
    }
    let imm26 = (word & 0x03ff_ffff) as i64;
    let off = ((imm26 << 38) >> 38) * 4; // 符号扩展 26 位
    (true, (pc as i64 + off) as u64)
}

/// MOVZ Xd, #imm16（64 位）解码：返回 (rd, imm16)。
fn decode_movz_64(word: u32) -> Option<(u8, u16)> {
    // sf=1 opc=10: 1 10 100101 00 imm16 Rd  -> 0xd2800000
    if word & 0xff80_0000 != 0xd280_0000 {
        return None;
    }
    let rd = (word & 0x1f) as u8;
    let imm16 = ((word >> 5) & 0xffff) as u16;
    Some((rd, imm16))
}

/// 直接从文件切片取一个可执行节区的 32 位指令数组（小端），
/// 并在其中扫描“mov xN,#超限长度; bl _recvfrom”签名。
///
/// 这是无源码定位的关键：不依赖函数名/符号表（剥离过的二进制同样适用），
/// 只依赖 (a) 导入表解析出的 recvfrom stub 地址，(b) 调用点的指令模式。
pub fn scan_bug_sites(data: &[u8], info: &MachOInfo) -> Result<Vec<BugSite>, PatchError> {
    let stub = info
        .stub_by_name("_recvfrom")
        .ok_or_else(|| PatchError("导入表中找不到 _recvfrom，无法定位网络读取点".into()))?;

    let mut hits = Vec::new();
    for sec in info.sections.iter().filter(|s| s.is_executable()) {
        let bytes = section_bytes(data, sec)?;
        if bytes.len() % 4 != 0 {
            return Err(PatchError(format!(
                "节区 {} 长度不是 4 的倍数",
                sec.name
            )));
        }
        let words: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        for i in 1..words.len() {
            let pc_bl = sec.vm_addr + (i as u64) * 4;
            let (is_bl, target) = decode_bl(words[i], pc_bl);
            if !is_bl || target != stub.vm_addr {
                continue;
            }
            if let Some((rd, imm)) = decode_movz_64(words[i - 1]) {
                hits.push(BugSite {
                    hook_vm: sec.vm_addr + ((i - 1) as u64) * 4,
                    original_word: words[i - 1],
                    oversized_len: imm,
                    len_reg: rd,
                    recvfrom_stub_vm: stub.vm_addr,
                });
            }
        }
    }
    Ok(hits)
}

fn section_bytes<'a>(data: &'a [u8], sec: &Section) -> Result<&'a [u8], PatchError> {
    let start = sec.file_off as usize;
    let end = start
        .checked_add(sec.size as usize)
        .ok_or_else(|| PatchError(format!("节区 {} 偏移溢出", sec.name)))?;
    data.get(start..end)
        .ok_or_else(|| PatchError(format!("节区 {} 的文件范围越界", sec.name)))
}

/// code cave 选择策略：
///   1) 优先专用 `__TEXT,__patchcave`（题目样例和固件常见预留区）；
///   2) 否则在可执行节区里找满足最小长度、4 字节对齐、不与任何已定义符号
///      重叠的全 0 指令流（udf #0，正常执行不可达）。
pub fn find_cave(
    data: &[u8],
    info: &MachOInfo,
    min_size: u64,
    hook_vm: u64,
) -> Result<(u64, u64, u64), PatchError> {
    if let Some(cave) = info.section_by_name("__TEXT", "__patchcave") {
        if cave.size < min_size {
            return Err(PatchError(format!(
                "__patchcave 仅 {} 字节，装不下 {} 字节补丁",
                cave.size, min_size
            )));
        }
        let bytes = section_bytes(data, cave)?;
        if bytes.iter().any(|&b| b != 0) {
            return Err(PatchError(
                "__patchcave 非空，拒绝覆盖可能有效的内容".into(),
            ));
        }
        return Ok((cave.vm_addr, cave.file_off, cave.size));
    }

    // 回退策略：在可执行节区找全 0 洞。
    for sec in info.sections.iter().filter(|s| s.is_executable()) {
        let bytes = section_bytes(data, sec)?;
        let mut run_start: Option<usize> = None;
        for (i, &b) in bytes.iter().enumerate() {
            if b == 0 {
                if run_start.is_none() {
                    run_start = Some(i);
                }
            } else if let Some(start) = run_start.take() {
                if let Some(hit) = check_zero_run(info, sec, bytes, start, i, min_size, hook_vm) {
                    return Ok(hit);
                }
            }
        }
        if let Some(start) = run_start {
            if let Some(hit) = check_zero_run(info, sec, bytes, start, bytes.len(), min_size, hook_vm)
            {
                return Ok(hit);
            }
        }
    }
    Err(PatchError(
        "找不到合适的 code cave（需要可执行节区内一段全 0 的对齐空闲区）".into(),
    ))
}

fn check_zero_run(
    info: &MachOInfo,
    sec: &Section,
    _bytes: &[u8],
    start: usize,
    end: usize,
    min_size: u64,
    hook_vm: u64,
) -> Option<(u64, u64, u64)> {
    // 对齐到 4 字节边界
    let start_aligned = (start + 3) & !3;
    if end <= start_aligned {
        return None;
    }
    let run_len = (end - start_aligned) as u64;
    if run_len < min_size {
        return None;
    }
    let cave_vm = sec.vm_addr + start_aligned as u64;
    let cave_end = cave_vm + run_len;
    // 不能落在任何已定义符号上
    for (_, addr) in &info.defined_symbols {
        if *addr >= cave_vm && *addr < cave_end {
            return None;
        }
    }
    // B 指令范围 ±128MiB
    let dist = cave_vm.abs_diff(hook_vm);
    if dist >= (1u64 << 25) {
        return None;
    }
    Some((cave_vm, sec.file_off + start_aligned as u64, run_len))
}

/// 生成补丁桩指令序列。
///
/// 寄存器选择 x16(IP0)/x17(IP1)：AAPCS64 规定的过程内临时寄存器，
/// 任何函数调用边界都不保证保留它们，因此在两条指令的窗口内借用绝对安全。
pub fn build_stub(site: &BugSite, cave_code_vm: u64, cap: u16) -> Result<Vec<u32>, PatchError> {
    if cap > 0xfff {
        return Err(PatchError(format!(
            "钳制上限 {cap} 超过 cmp 立即数 12 位范围"
        )));
    }
    let tmp = 16u8; // x16
    let len = site.len_reg;
    let mut words: Vec<u32> = Vec::new();

    // 1) 把原始长度搬进临时寄存器（x2 本身要在最后被重写）
    words.push(arm64::encode_mov_reg(tmp, len).map_err(pe)?);
    // 2) 与缓冲区容量比较
    words.push(arm64::encode_cmp_imm(tmp, cap).map_err(pe)?);
    // 3) 原始长度 <= cap：跳过钳制，保留原值
    let b_ls_pc = cave_code_vm + 2 * 4;
    let b_ls_target = cave_code_vm + 4 * 4; // 跳到第 5 条
    words.push(arm64::encode_b_ls(b_ls_pc, b_ls_target).map_err(pe)?);
    // 4) 超限：x2 = cap
    words.push(arm64::encode_movz(len, cap).map_err(pe)?);
    // 5) 跳回 recvfrom 调用（被替换指令的下一条，即 bl 本身）
    let return_vm = site.hook_vm + 4;
    words.push(arm64::encode_b(cave_code_vm + 4 * 4, return_vm).map_err(pe)?);

    Ok(words)
}

fn pe(e: arm64::EncodeError) -> PatchError {
    PatchError(e.0)
}

/// 产出完整补丁计划（不写文件）。
pub fn plan_patch(data: &[u8], info: &MachOInfo, cap: Option<u16>) -> Result<PatchPlan, PatchError> {
    let sites = scan_bug_sites(data, info)?;
    let site = match sites.len() {
        0 => {
            return Err(PatchError(
                "没有匹配到 'mov xN,#超限长度; bl _recvfrom' 签名，目标可能已打过补丁或编译模式不同".into(),
            ))
        }
        1 => sites.into_iter().next().unwrap(),
        n => {
            let list: Vec<String> = sites
                .iter()
                .map(|s| format!("{:#x}(len={})", s.hook_vm, s.oversized_len))
                .collect();
            return Err(PatchError(format!(
                "匹配到 {n} 个缺陷点（{list:?}），本版本只处理单点；请用 --cap/确认目标后处理"
            )));
        }
    };

    if site.len_reg != 2 {
        return Err(PatchError(format!(
            "缺陷点长度寄存器是 x{} 而不是预期的 x2，为稳妥起见中止",
            site.len_reg
        )));
    }
    let cap = cap.unwrap_or_else(|| {
        // 字符串缓冲区的安全接收长度：容量 64 - NUL 终止符 1 = 63。
        // 可由 --cap 覆盖（非字符串的裸字节缓冲可用满整个容量）。
        63u16
    });
    if cap as u32 >= site.oversized_len as u32 {
        return Err(PatchError(format!(
            "钳制上限 {} 不小于原始长度 {}，补丁没有意义，中止",
            cap, site.oversized_len
        )));
    }

    // 桩 5 条指令 + 28 字节元数据
    let need = (CODE_OFF + 5 * 4) as u64;
    let (cave_vm, cave_file_off, cave_size) = find_cave(data, info, need, site.hook_vm)?;
    let cave_code_vm = cave_vm + CODE_OFF as u64;
    let stub_words = build_stub(&site, cave_code_vm, cap)?;

    Ok(PatchPlan {
        site,
        cave_vm,
        cave_file_off,
        cave_size,
        cap,
        stub_words,
    })
}

/// 把计划应用到文件缓冲（原地改字节，不改变文件长度）。
pub fn apply_patch(data: &mut [u8], info: &MachOInfo, plan: &PatchPlan) -> Result<(), PatchError> {
    // 防重复：洞穴 magic 已存在则拒绝
    let cave_off = plan.cave_file_off as usize;
    let meta_end = cave_off + META_SIZE;
    if data.len() < meta_end + plan.stub_words.len() * 4 {
        return Err(PatchError("文件太短，写入会越界".into()));
    }
    if data[cave_off..cave_off + 4] == MAGIC {
        return Err(PatchError(
            "洞穴已含 HPC1 标记，目标似乎已打过补丁；请先恢复备份".into(),
        ));
    }
    // 再次确认洞穴代码区全 0
    let code_len = plan.stub_words.len() * 4;
    if data[cave_off..cave_off + META_SIZE + code_len]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(PatchError("补丁目标区域非全 0，拒绝覆盖".into()));
    }

    // ---- 写元数据 ----
    data[cave_off..cave_off + 4].copy_from_slice(&MAGIC);
    data[cave_off + 4..cave_off + 8]
        .copy_from_slice(&plan.site.original_word.to_le_bytes());
    data[cave_off + 8..cave_off + 12].copy_from_slice(&(plan.cap as u32).to_le_bytes());
    data[cave_off + 12..cave_off + 20].copy_from_slice(&plan.site.hook_vm.to_le_bytes());
    data[cave_off + 20..cave_off + 28].copy_from_slice(&plan.site.recvfrom_stub_vm.to_le_bytes());
    data[cave_off + 28..cave_off + 36]
        .copy_from_slice(&(plan.site.hook_vm + 4).to_le_bytes());
    data[cave_off + 36..cave_off + 44].copy_from_slice(&(plan.cave_vm + CODE_OFF as u64).to_le_bytes());

    // ---- 写桩代码 ----
    for (i, w) in plan.stub_words.iter().enumerate() {
        let p = cave_off + CODE_OFF + i * 4;
        data[p..p + 4].copy_from_slice(&w.to_le_bytes());
    }

    // ---- 改写钩子：原 mov 指令 -> B cave ----
    let hook_file = info
        .vm_to_file(plan.site.hook_vm)
        .ok_or_else(|| PatchError("钩子地址无法翻译到文件偏移".into()))? as usize;
    let branch = arm64::encode_b(plan.site.hook_vm, plan.cave_vm + CODE_OFF as u64)
        .map_err(pe)?;
    data[hook_file..hook_file + 4].copy_from_slice(&branch.to_le_bytes());

    Ok(())
}

/// 从已打补丁的文件中读回补丁元数据，供 verify 使用。
#[derive(Debug, Clone)]
pub struct InstalledPatch {
    pub hook_vm: u64,
    pub original_word: u32,
    pub cap: u32,
    pub recvfrom_stub_vm: u64,
    pub return_vm: u64,
    pub cave_code_vm: u64,
    pub cave_vm: u64,
}

pub fn read_installed(data: &[u8], info: &MachOInfo) -> Result<InstalledPatch, PatchError> {
    let cave = info
        .section_by_name("__TEXT", "__patchcave")
        .ok_or_else(|| PatchError("没有 __patchcave 节区，无法校验本工具安装的补丁".into()))?;
    let off = cave.file_off as usize;
    if data.len() < off + META_SIZE {
        return Err(PatchError("洞穴读取越界".into()));
    }
    if data[off..off + 4] != MAGIC {
        return Err(PatchError("未找到 HPC1 标记，目标未打补丁".into()));
    }
    let rd = |o: usize| u32::from_le_bytes(data[off + o..off + o + 4].try_into().unwrap());
    let rq = |o: usize| u64::from_le_bytes(data[off + o..off + o + 8].try_into().unwrap());
    Ok(InstalledPatch {
        original_word: rd(4),
        cap: rd(8),
        hook_vm: rq(12),
        recvfrom_stub_vm: rq(20),
        return_vm: rq(28),
        cave_code_vm: rq(36),
        cave_vm: cave.vm_addr,
    })
}
