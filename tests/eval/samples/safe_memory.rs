// 無漏洞：安全的 Rust 記憶體操作
fn get_element(data: &[i32], index: usize) -> Option<i32> {
    // 使用安全的邊界檢查存取
    data.get(index).copied()
}

fn main() {
    let data = vec![1, 2, 3];
    match get_element(&data, 10) {
        Some(v) => println!("{}", v),
        None => println!("Index out of bounds"),
    }
}
