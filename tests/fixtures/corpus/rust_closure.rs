fn main() { let offset = 3; let callback = |value: i32| value + offset; assert_eq!(callback(2), 5); }
