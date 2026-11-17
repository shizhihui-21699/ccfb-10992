//! hotpatch —— 无源码 arm64 Mach-O 热补丁工具。
//!
//! 子命令：
//!   info   <bin>                  解析并打印节区、导入 stub、缺陷点扫描结果（只读）
//!   patch  <bin> [-o out] [--cap N] [--no-backup] [--no-codesign]
//!   verify <bin>                  校验已安装补丁的完整性与跳转目标
//!
//! 设计原则见 patcher.rs 模块注释。

mod arm64;
mod macho_info;
mod patcher;

use macho_info::parse;
use patcher::{apply_patch, plan_patch, read_installed, scan_bug_sites, META_SIZE};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    let res = match args[1].as_str() {
        "info" => cmd_info(&args[2..]),
        "patch" => cmd_patch(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("未知子命令 {other:?}\n\n{}", usage())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hotpatch: 错误: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "hotpatch — 无源码 arm64 Mach-O recvfrom 长度检查热补丁\n\
\n\
用法:\n  \
hotpatch info   <二进制>\n  \
hotpatch patch  <二进制> [-o 输出文件] [--cap 长度] [--no-backup] [--no-codesign]\n  \
hotpatch verify <二进制>\n"
        .into()
}

struct PatchArgs {
    input: PathBuf,
    output: Option<PathBuf>,
    cap: Option<u16>,
    backup: bool,
    codesign: bool,
}

fn parse_patch_args(a: &[String]) -> Result<PatchArgs, String> {
    if a.is_empty() {
        return Err("缺少二进制路径参数".into());
    }
    let mut input: Option<PathBuf> = None;
    let mut output = None;
    let mut cap = None;
    let mut backup = true;
    let mut codesign = true;
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "-o" => {
                i += 1;
                output = Some(PathBuf::from(a.get(i).ok_or("-o 缺少参数")?));
            }
            "--cap" => {
                i += 1;
                let v: u16 = a
                    .get(i)
                    .ok_or("--cap 缺少参数")?
                    .parse()
                    .map_err(|_| "--cap 需要 1..=4095 的整数")?;
                cap = Some(v);
            }
            "--no-backup" => backup = false,
            "--no-codesign" => codesign = false,
            other if !other.starts_with('-') => {
                if input.is_some() {
                    return Err("只能指定一个输入二进制".into());
                }
                input = Some(PathBuf::from(other));
            }
            other => return Err(format!("未知参数 {other}")),
        }
        i += 1;
    }
    Ok(PatchArgs {
        input: input.ok_or("缺少二进制路径参数")?,
        output,
        cap,
        backup,
        codesign,
    })
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(args.first().ok_or("缺少二进制路径参数")?);
    let data = std::fs::read(&path).map_err(|e| format!("读取失败: {e}"))?;
    let info = parse(&path).map_err(|e| e.0)?;

    println!("== Mach-O 概览: {} ==", path.display());
    println!("入口点: {:#x}", info.entry);
    println!("\n-- 节区 ({}) --", info.sections.len());
    for s in &info.sections {
        println!(
            "  {:<16} {:<8} vm={:#012x} size={:#07x} off={:#07x}{}",
            s.segment,
            s.name,
            s.vm_addr,
            s.size,
            s.file_off,
            if s.is_executable() { " [X]" } else { "" }
        );
    }

    println!("\n-- 导入 stub ({}) --", info.stubs.len());
    for st in &info.stubs {
        println!("  {:#012x}  {}", st.vm_addr, st.symbol);
    }

    println!("\n-- 已定义符号 ({}，仅展示前 20 个) --", info.defined_symbols.len());
    for (n, a) in info.defined_symbols.iter().take(20) {
        println!("  {:#012x}  {}", a, n);
    }

    println!("\n-- 缺陷点扫描（mov xN,#len; bl _recvfrom 签名）--");
    match scan_bug_sites(&data, &info) {
        Ok(sites) if sites.is_empty() => {
            println!("  未发现匹配签名（可能已打补丁，或编译模式不同）");
        }
        Ok(sites) => {
            for s in &sites {
                let owner = info
                    .symbol_containing(s.hook_vm)
                    .map(|(n, a)| format!("，位于 {n}+{:#x}", s.hook_vm - a))
                    .unwrap_or_default();
                println!(
                    "  命中: hook={:#x}  原始指令={:#010x}  长度寄存器=x{}  失控长度={}  recvfrom_stub={:#x}{}",
                    s.hook_vm, s.original_word, s.len_reg, s.oversized_len, s.recvfrom_stub_vm, owner
                );
            }
        }
        Err(e) => println!("  扫描失败: {}", e.0),
    }
    Ok(())
}

fn cmd_patch(args: &[String]) -> Result<(), String> {
    let pa = parse_patch_args(args)?;
    let data = std::fs::read(&pa.input).map_err(|e| format!("读取失败: {e}"))?;
    let info = parse(&pa.input).map_err(|e| e.0)?;

    let plan = plan_patch(&data, &info, pa.cap).map_err(|e| e.0)?;
    println!("== 补丁计划 ==");
    println!(
        "缺陷点      : {:#x}（原始指令 {:#010x}：mov x{}, #{}）",
        plan.site.hook_vm, plan.site.original_word, plan.site.len_reg, plan.site.oversized_len
    );
    println!(
        "recvfrom    : stub {:#x}",
        plan.site.recvfrom_stub_vm
    );
    println!(
        "code cave   : vm={:#x} file_off={:#x} 容量={:#x} 字节",
        plan.cave_vm, plan.cave_file_off, plan.cave_size
    );
    println!("钳制上限    : {} 字节（recvfrom 实际最多收这么多）", plan.cap);
    println!("桩指令      : {} 条 / {} 字节", plan.stub_words.len(), plan.stub_words.len() * 4);
    for (i, w) in plan.stub_words.iter().enumerate() {
        println!("  {:#x}: {:#010x}", plan.cave_vm + META_SIZE as u64 + (i as u64) * 4, w);
    }

    let mut buf = data;
    apply_patch(&mut buf, &info, &plan).map_err(|e| e.0)?;

    // 决定输出路径
    let out_path: PathBuf = match &pa.output {
        Some(p) => p.clone(),
        None => pa.input.clone(),
    };

    // 原地改写前先备份
    if pa.backup && out_path == pa.input {
        let bak = backup_name(&pa.input);
        std::fs::copy(&pa.input, &bak)
            .map_err(|e| format!("备份到 {} 失败: {e}", bak.display()))?;
        println!("已备份原文件: {}", bak.display());
    }

    std::fs::write(&out_path, &buf).map_err(|e| format!("写入失败: {e}"))?;
    // 保持可执行位
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(&out_path, perm);
    }
    println!("已写入补丁文件: {}", out_path.display());

    if pa.codesign {
        match re_sign(&out_path) {
            Ok(()) => println!("已重新 ad-hoc 签名（codesign --force --sign -）"),
            Err(e) => {
                eprintln!(
                    "警告: 重签失败（{e}）。arm64 macOS 上签名失效的二进制会被内核拒绝执行，\
                     可手动执行: codesign --force --sign - {}",
                    out_path.display()
                );
            }
        }
    } else {
        println!("已跳过签名（--no-codesign）；注意 arm64 macOS 可能拒绝执行未签名/签名失效程序");
    }
    Ok(())
}

fn backup_name(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".orig");
    PathBuf::from(s)
}

/// 校验用的原始参考文件：优先 <bin>.orig；否则把 .patched 后缀去掉找原文件。
fn resolve_reference(patched: &Path) -> Option<PathBuf> {
    let bak = backup_name(patched);
    if bak.exists() {
        return Some(bak);
    }
    if patched.extension().and_then(|e| e.to_str()) == Some("patched") {
        let stem = patched.with_extension(""); // 去掉 .patched
        if stem.exists() {
            return Some(stem);
        }
    }
    None
}

fn re_sign(p: &Path) -> Result<(), String> {
    let out = std::process::Command::new("codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg(p)
        .output()
        .map_err(|e| format!("无法启动 codesign: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let path = PathBuf::from(args.first().ok_or("缺少二进制路径参数")?);
    let data = std::fs::read(&path).map_err(|e| format!("读取失败: {e}"))?;
    let info = parse(&path).map_err(|e| e.0)?;
    let inst = read_installed(&data, &info).map_err(|e| e.0)?;

    println!("== 补丁校验: {} ==", path.display());
    println!("洞穴标记    : HPC1 存在 @ {:#x}", inst.cave_vm);
    println!("钩子地址    : {:#x}", inst.hook_vm);
    println!("原始指令    : {:#010x}", inst.original_word);
    println!("钳制上限    : {}", inst.cap);
    println!("recvfrom    : {:#x}", inst.recvfrom_stub_vm);
    println!("桩入口      : {:#x}", inst.cave_code_vm);

    let mut ok = true;

    // 1) 钩子处必须是一条跳到桩入口的 B
    let hook_off = info.vm_to_file(inst.hook_vm).ok_or("钩子地址无法翻译")? as usize;
    let hook_word = u32::from_le_bytes(data[hook_off..hook_off + 4].try_into().unwrap());
    let expected_b = arm64::encode_b(inst.hook_vm, inst.cave_code_vm).map_err(|e| e.0)?;
    if hook_word != expected_b {
        ok = false;
        println!(
            "[失败] 钩子指令 {:#010x} 与预期 B {:#010x} 不符",
            hook_word, expected_b
        );
    } else {
        println!("[通过] 钩子为 B -> {:#x}", inst.cave_code_vm);
    }

    // 2) 桩的最后一条必须是回到 hook+4（即原 bl _recvfrom）的 B
    let cave_off = info
        .vm_to_file(inst.cave_vm)
        .ok_or("洞穴地址无法翻译")? as usize;
    let code_off = cave_off + META_SIZE;
    let words: Vec<u32> = (0..5)
        .map(|i| u32::from_le_bytes(data[code_off + i * 4..code_off + i * 4 + 4].try_into().unwrap()))
        .collect();
    let last_pc = inst.cave_code_vm + 4 * 4;
    let expected_ret = arm64::encode_b(last_pc, inst.return_vm).map_err(|e| e.0)?;
    if words[4] != expected_ret || inst.return_vm != inst.hook_vm + 4 {
        ok = false;
        println!("[失败] 桩返回链路错误: {:#010x}", words[4]);
    } else {
        println!("[通过] 桩末尾 B -> {:#x}（原 bl _recvfrom）", inst.return_vm);
    }

    // 3) 重新扫描缺陷签名：原来的点必须已消失（B 不再是 movz）
    let sites = scan_bug_sites(&data, &info).unwrap_or_default();
    if sites.iter().any(|s| s.hook_vm == inst.hook_vm) {
        ok = false;
        println!("[失败] 缺陷点仍然可被签名扫描命中，补丁未生效");
    } else {
        println!("[通过] 原始缺陷签名已消失（共扫到 {} 个其它点）", sites.len());
    }

    // 4) 元数据里的 recvfrom 必须仍是当前导入表中的 stub
    match info.stub_by_name("_recvfrom") {
        Some(st) if st.vm_addr == inst.recvfrom_stub_vm => {
            println!("[通过] recvfrom stub 绑定未变 ({:#x})", st.vm_addr)
        }
        Some(st) => {
            ok = false;
            println!(
                "[失败] recvfrom stub 漂移: 元数据 {:#x} vs 导入表 {:#x}",
                inst.recvfrom_stub_vm, st.vm_addr
            );
        }
        None => {
            ok = false;
            println!("[失败] 导入表中已无 _recvfrom");
        }
    }

    // 5) 逐节区比对原始备份：补丁只允许改 __patchcave 与钩子处 4 字节。
    //    重签会重写 load command / __LINKEDIT / 签名块（文件可能变长），
    //    这些不属于代码补丁，按节区比对即可正确排除。
    if let Some(ref_path) = resolve_reference(Path::new(args.first().unwrap())) {
        let orig = std::fs::read(&ref_path).map_err(|e| format!("读原始文件失败: {e}"))?;
        let orig_info = parse(&ref_path).map_err(|e| e.0)?;
        let cave_sec = info
            .section_by_name("__TEXT", "__patchcave")
            .ok_or("缺少 __patchcave 节区")?;
        let cave_range =
            cave_sec.file_off as usize..(cave_sec.file_off + cave_sec.size) as usize;
        let hook_file = info.vm_to_file(inst.hook_vm).ok_or("钩子地址无法翻译")? as usize;
        let hook_range = hook_file..hook_file + 4;

        let mut section_issues = 0usize;
        for sec in &info.sections {
            // 与原始文件按 (段,节) 名配对；只比对两边都存在、且有文件内容的节区
            let o = match orig_info.section_by_name(&sec.segment, &sec.name) {
                Some(o) if o.size == sec.size => o,
                _ => continue,
            };
            let cur = data
                .get(sec.file_off as usize..(sec.file_off + sec.size) as usize)
                .ok_or("当前文件节区越界")?;
            let old = orig
                .get(o.file_off as usize..(o.file_off + o.size) as usize)
                .ok_or("原始文件节区越界")?;
            for (i, (a, b)) in old.iter().zip(cur.iter()).enumerate() {
                if a == b {
                    continue;
                }
                let abs = sec.file_off as usize + i;
                let allowed = cave_range.contains(&abs) || hook_range.contains(&abs);
                if !allowed {
                    section_issues += 1;
                    if section_issues <= 5 {
                        println!(
                            "[失败] 节区 {}.{} 在 {:#x} 出现非预期改动",
                            sec.segment, sec.name, sec.vm_addr + i as u64
                        );
                    }
                }
            }
        }
        if section_issues == 0 {
            println!(
                "[通过] 逐节区比对：除 __patchcave 与钩子 {:#x} 4 字节外，所有节区逐字节一致",
                inst.hook_vm
            );
            println!("       （load command / __LINKEDIT / 签名块的差异为重签产物，不计入代码改动）");
        } else {
            ok = false;
            println!("[失败] 共 {section_issues} 处节区改动落在允许范围之外");
        }
    } else {
        println!("[跳过] 未找到原始参考文件（.orig 或同名未打补丁文件），无法做逐字节差异比对");
    }

    if ok {
        println!("\n结论: 补丁安装完整且自洽。");
        Ok(())
    } else {
        Err("校验发现问题，详见上面的 [失败] 项".into())
    }
}
