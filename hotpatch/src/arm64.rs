//! arm64 (AArch64) 指令编码器 —— 只用确定的编码，不依赖外部汇编器。
//!
//! 补丁本身的正确性首先建立在编码正确上，因此每个编码器都配了单元测试，
//! 测试期望值用 clang/llvm-mc 交叉核对过（见 tests/ 下的参考汇编）。

#![allow(clippy::needless_return)]

/// 编码过程中的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError(pub String);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for EncodeError {}

/// 无条件分支 B（±128 MiB）。
/// `pc` / `target` 都是绝对虚拟地址；返回指令字。
pub fn encode_b(pc: u64, target: u64) -> Result<u32, EncodeError> {
    let off = (target as i64) - (pc as i64);
    if off % 4 != 0 {
        return Err(EncodeError(format!("B: 目标 {target:#x} 未按 4 字节对齐")));
    }
    let imm26 = off / 4;
    if !(-(1i64 << 25)..(1i64 << 25)).contains(&imm26) {
        return Err(EncodeError(format!(
            "B: 偏移 {off} 超出 ±128MiB 范围（pc={pc:#x}, target={target:#x}）"
        )));
    }
    // op=0 (B), imm26
    return Ok(0x1400_0000u32 | ((imm26 as u32) & 0x03ff_ffff));
}

/// MOVZ Xd, #imm16（64 位宽 sf=1）。
pub fn encode_movz(rd: u8, imm16: u16) -> Result<u32, EncodeError> {
    check_reg(rd)?;
    return Ok(0xd280_0000 | ((imm16 as u32) << 5) | rd as u32);
}

/// MOVK Xd, #imm16, LSL #shift（shift 必须是 0/16/32/48）。
#[allow(dead_code)] // 由 encode_mov_imm64 与单元测试使用，作为编码器库能力保留
pub fn encode_movk(rd: u8, imm16: u16, shift: u8) -> Result<u32, EncodeError> {
    check_reg(rd)?;
    let hw = match shift {
        0 => 0u32,
        16 => 1,
        32 => 2,
        48 => 3,
        _ => return Err(EncodeError(format!("MOVK: 非法移位 {shift}"))),
    };
    return Ok(0xf280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd as u32);
}

/// CMP Xn, #imm（SUBS XZR, Xn, #imm）。仅支持 12 位无符号立即数。
pub fn encode_cmp_imm(rn: u8, imm12: u16) -> Result<u32, EncodeError> {
    check_reg(rn)?;
    if imm12 > 0xfff {
        return Err(EncodeError(format!("CMP: 立即数 {imm12} 超过 12 位")));
    }
    // sf=1 op=1 S=1(0x7f...): 1110 0001 00 imm12 Rn 11111
    return Ok(0xf100_001f | ((imm12 as u32) << 10) | ((rn as u32) << 5));
}

/// B.LS（无符号 <= 跳转，即 CMP 后的 cc=LS = 1001 = 0x9）。
/// 注意与 CC/LO(0x3，严格小于) 区分：本补丁需要的是“原长度 <= 容量”。
pub fn encode_b_ls(pc: u64, target: u64) -> Result<u32, EncodeError> {
    let off = (target as i64) - (pc as i64);
    if off % 4 != 0 {
        return Err(EncodeError(format!("B.LS: 目标未 4 字节对齐")));
    }
    let imm19 = off / 4;
    if !(-(1i64 << 18)..(1i64 << 18)).contains(&imm19) {
        return Err(EncodeError("B.LS: 偏移超出 ±1MiB".into()));
    }
    // 0101 0100 imm19 0 cond=1001(LS)
    return Ok(0x5400_0009 | (((imm19 as u32) & 0x7ffff) << 5));
}

/// MOV Xd, Xn（ORR Xd, XZR, Xn）。
pub fn encode_mov_reg(rd: u8, rn: u8) -> Result<u32, EncodeError> {
    check_reg(rd)?;
    check_reg(rn)?;
    // ORR (shifted register, 64-bit): 1010 1010 000 Rm 000000 11111 Rd
    return Ok(0xaa00_03e0 | ((rn as u32) << 16) | rd as u32);
}

fn check_reg(r: u8) -> Result<(), EncodeError> {
    if r > 31 {
        return Err(EncodeError(format!("寄存器号 {r} 越界")));
    }
    Ok(())
}

/// 把 64 位立即数 `imm` 用 movz + movk 装载到 `rd`。
///
/// 规则（与 llvm-mc 一致）：以最低 16 位做 movz，之后每一个更高的半字都必须
/// 有一条 movk（不能跳过中间的 0 半字，否则 movk 的移位位置就错了），
/// 直到最高的非零半字为止。全 0 时只发一条 movz。
#[allow(dead_code)] // 当前桩用 movz+cmp 即可；保留供需要装载 64 位地址的更复杂桩
pub fn encode_mov_imm64(rd: u8, imm: u64) -> Result<Vec<u32>, EncodeError> {
    let halves: [u16; 4] = [
        (imm & 0xffff) as u16,
        ((imm >> 16) & 0xffff) as u16,
        ((imm >> 32) & 0xffff) as u16,
        ((imm >> 48) & 0xffff) as u16,
    ];
    let highest = halves
        .iter()
        .rposition(|&h| h != 0)
        .unwrap_or(0); // 全 0 时只发 movz x, #0
    let mut out = Vec::with_capacity(highest + 1);
    out.push(encode_movz(rd, halves[0])?);
    for shift_idx in 1..=highest {
        let shift = (shift_idx as u8) * 16;
        out.push(encode_movk(rd, halves[shift_idx], shift)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn movz_movk_imm64() {
        // movz x8, #0x800  -> d2810008（与 clang/llvm-mc 交叉核对）
        assert_eq!(encode_movz(8, 0x0800).unwrap(), 0xd281_0008);
        // movz x16, #0x0   -> d2800010
        assert_eq!(encode_movz(16, 0).unwrap(), 0xd280_0010);
        // movk x16, #0x1, lsl #16 -> f2a00030（clang 交叉核对）
        assert_eq!(encode_movk(16, 1, 16).unwrap(), 0xf2a0_0030);
        // 0x100000a90 -> movz #0xa90 ; movk #0,lsl16 ; movk #1,lsl32
        let seq = encode_mov_imm64(16, 0x1_0000_0a90).unwrap();
        assert_eq!(seq, vec![0xd281_5210, 0xf2a0_0010, 0xf2c0_0030]);
        // 0
        assert_eq!(encode_mov_imm64(9, 0).unwrap(), vec![0xd280_0009]);
    }

    #[test]
    fn cmp_and_cond_branch() {
        // cmp x8, #0x40  -> f101011f
        assert_eq!(encode_cmp_imm(8, 0x40).unwrap(), 0xf101_011f);
        // b.ls +8（pc=0, target=8 -> imm19=2, cond=LS=9）-> 0x54000049
        assert_eq!(encode_b_ls(0, 8).unwrap(), 0x5400_0049);
    }

    #[test]
    fn mov_reg_and_b() {
        // mov x2, x8 -> aa0803e2（clang 交叉核对）
        assert_eq!(encode_mov_reg(2, 8).unwrap(), 0xaa08_03e2);
        // b 到 0x10000acc，pc=0x100000800：off=0x2cc, imm26=0xb3
        let w = encode_b(0x10000_0800, 0x10000_0acc).unwrap();
        assert_eq!(w, 0x1400_00b3);
        // 反向：从 cave 回 0x100000804，imm26 = -181（0x3ffff4b）
        let w2 = encode_b(0x10000_0ad8, 0x10000_0804).unwrap();
        assert_eq!(w2, 0x17ff_ff4b);
    }

    #[test]
    fn range_checks() {
        assert!(encode_b(0, 1u64 << 27).is_err());
        assert!(encode_cmp_imm(0, 4096).is_err());
        assert!(encode_movz(32, 0).is_err());
    }
}
