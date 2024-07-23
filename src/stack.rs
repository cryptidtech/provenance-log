// SPDX-License-Identifier: FSL-1.1
use log::info;
use std::fmt;
use wacc::{Stack, vm::Value};

/// Stack is used for both the parameter and return value stacks in the WACC vm
#[derive(Clone, Default)]
pub struct Stk {
    stack: Vec<Value>
}

impl Stack for Stk {
    /// push a value onto the stack
    fn push(&mut self, value: Value) {
        info!("push: {:?}", &value);
        info!(println!("{:?}", &self));
        self.stack.push(value);
    }

    /// remove the last top value from the stack
    fn pop(&mut self) -> Option<Value> {
        match self.top() {
            Some(v) => info!("pop: {:?}", &v),
            None => info!("pop from empty stack"),
        }
        info!(println!("{:?}", &self));
        self.stack.pop()
    }

    /// get a reference to the top value on the stack 
    fn top(&self) -> Option<Value> {
        self.stack.last().cloned()
    }

    /// peek at the item at the given index
    fn peek(&self, idx: usize) -> Option<Value> {
        if idx >= self.stack.len() {
            return None;
        }
        Some(self.stack[self.stack.len() - 1 - idx].clone())
    }

    /// return the number of values on the stack
    fn len(&self) -> usize {
        self.stack.len()
    }

    /// return if the stack is empty
    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

impl fmt::Debug for Stk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut max_len = 0;
        let values = self.stack.iter().rev().map(|v| {
            let s = format!("{:?}", v);
            if s.len() > max_len {
                max_len = s.len()
            }
            s
        }).collect::<Vec<String>>();
        let mut first = true;
        let mut s = format!("       ╭─{:─<max_len$}─╮\n", "─");
        values.iter().for_each(|l| {
            if first {
                s += format!(" top → │ {} │\n", l).as_str();
                first = false;
            } else {
                s += format!("       │ {} │\n", l).as_str();
            }
            s += format!("       ├─{:─<max_len$}─┤\n", "─").as_str();
        });
        s += format!("       ┆ {:<max_len$} ┆", " ").as_str();
        f.write_str(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_binary() {
        let mut s = Stk::default();
        s.push(b"foo".to_vec().into());
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Bin(b"foo".to_vec())));
    }

    #[test]
    fn test_push_string() {
        let mut s = Stk::default();
        s.push("foo".to_string().into());
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Str("foo".to_string())));
    }

    #[test]
    fn test_push_success() {
        let mut s = Stk::default();
        s.push(1.into());
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Success(1)));
    }

    #[test]
    fn test_push_failure() {
        let mut s = Stk::default();
        s.push(Value::Failure("bad".to_string()));
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Failure("bad".to_string())));
    }

    #[test]
    fn test_pop() {
        let mut s = Stk::default();
        s.push(1.into());
        s.push(2.into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.top(), Some(Value::Success(2)));
        s.pop();
        assert_eq!(s.len(), 1);
        assert_eq!(s.top(), Some(Value::Success(1)));
    }

    #[test]
    fn test_peek() {
        let mut s = Stk::default();
        s.push(1.into());
        s.push(2.into());
        assert_eq!(s.len(), 2);
        assert_eq!(s.peek(1), Some(Value::Success(1)));
    }

    #[test]
    fn test_debug() {
        let mut s = Stk::default();
        s.push(1.into());
        s.push(2.into());
        assert_eq!(s.len(), 2);
        println!("{:?}", s);
        assert_eq!(format!("{:?}", s), "╭────────────╮\n top → │ Success(2) │\n       ├────────────┤\n       │ Success(1) │\n       ├────────────┤\n       ┆            ┆".to_string());
    }
}
