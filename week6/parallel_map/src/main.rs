use crossbeam_channel;
use std::{
    fmt::Debug,
    thread,
    time::{self, Instant},
};

fn parallel_map<T, U, F>(input_vec: Vec<T>, num_threads: usize, f: F) -> Vec<U>
where
    F: FnOnce(T) -> U + Send + Copy + 'static,
    T: Send + 'static,
    U: Send + 'static + Default + Debug,
{
    let mut output_vec: Vec<U> = Vec::with_capacity(input_vec.len());
    unsafe {
        output_vec.set_len(output_vec.capacity());
    }
    let (input_tx, input_rx) = crossbeam_channel::unbounded::<(usize, T)>();
    let (output_tx, output_rx) = crossbeam_channel::unbounded::<(usize, U)>();
    input_vec.into_iter().enumerate().for_each(|(idx, item)| {
        let _ = input_tx.send((idx, item));
    });
    std::thread::scope(|s| {
        for _ in 0..num_threads {
            let input_rx = input_rx.clone();
            let output_tx = output_tx.clone();
            s.spawn(move || {
                while let Ok((idx, item)) = input_rx.recv() {
                    let _ = output_tx.send((idx, f(item)));
                }
            });
        }
        s.spawn(move || {
            drop(input_tx);
            drop(output_tx);
        });
    });
    while let Ok((idx, item)) = output_rx.recv() {
        output_vec[idx] = item;
    }
    output_vec
}

fn main() {
    let start = Instant::now();
    let v = vec![6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 12, 18, 11, 5, 20];
    let squares = parallel_map(v, 10, |num| {
        println!("{} squared is {}", num, num * num);
        thread::sleep(time::Duration::from_millis(500));
        num * num
    });
    println!("squares: {:?}", squares);
    println!("time takes {:?}", start.elapsed());
}
