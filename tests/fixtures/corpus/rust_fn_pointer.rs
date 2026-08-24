fn add(value: i32) -> i32 { value + 4 }
fn main() { let callback: fn(i32) -> i32 = add; assert_eq!(callback(1), 5); }
