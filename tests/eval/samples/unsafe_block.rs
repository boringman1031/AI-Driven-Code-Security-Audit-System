// CWE-787: Unsafe Block Rust（含漏洞）
fn main() {
    let data: Vec<i32> = vec![1, 2, 3];
    let ptr = data.as_ptr();

    // unsafe 區塊：手動指標運算，存在越界存取風險
    unsafe {
        // 存取超出 Vec 範圍的記憶體（index 10 超出 len=3）
        let val = *ptr.offset(10);
        println!("{}", val);
    }
}
