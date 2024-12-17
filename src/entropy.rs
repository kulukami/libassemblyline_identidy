pub struct Entropy {
    pub byte_count: [u64; 256],
    pub length: usize,
}

impl Entropy {
    pub fn new(length: usize) -> Entropy {
        let mut byte_count = [0u64; 256];

        Entropy {
            byte_count: byte_count,
            length: length,
        }
    }

    pub fn update(&mut self, buf: &[u8]) {
        for byte in buf {
            self.byte_count[*byte as usize] += 1
        }
    }

    pub fn finalize(&self) -> f32 {
        let mut entropy = 0f32;
        for &count in self.byte_count.iter() {
            if count != 0 {
                let symbol_probability = count as f32 / self.length as f32;
                entropy += symbol_probability * symbol_probability.log2();
            }
        }
        -entropy
    }
}

pub struct EntropyBuckets {
    pub byte_count: [[u64; 256]; 50],
    pub length: usize,
    pub bucketsize: usize,
    pub curp: usize,
}

impl EntropyBuckets {
    pub fn new(length: usize) -> EntropyBuckets {
        let mut byte_count: [[u64; 256]; 50] = [[0u64; 256]; 50];
        let bucketsize = match length % 50 > 0 {
            true => length / 50 + 1,
            false => length / 50,
        };
        EntropyBuckets {
            byte_count: byte_count,
            length: length,
            bucketsize: bucketsize,
            curp: 0,
        }
    }
    pub fn update(&mut self, buf: &[u8]) {
        let mut bucket_idx: usize = 0;
        for idx in 0..buf.len() {
            bucket_idx = self.curp / self.bucketsize;
            self.byte_count[bucket_idx][buf[idx] as usize] += 1;
            self.curp += 1;
        }
    }
    pub fn finalize(&self) -> Vec<f32> {
        let mut result = Vec::new();
        for each_bucket in &self.byte_count {
            let mut entropy = 0f32;
            let bucketsize: u64 = each_bucket.iter().sum();
            for &count in each_bucket.iter() {
                if count != 0 {
                    let symbol_probability = count as f32 / bucketsize as f32;
                    entropy += symbol_probability * symbol_probability.log2();
                }
            }
            result.push(-entropy);
        }
        return result;
    }
}

pub fn entropy_from_buf(buf: &[u8]) -> f32 {
    let mut byte_count = [0u64; 256];
    for byte in buf.iter() {
        byte_count[*byte as usize] += 1
    }

    let mut entropy = 0f32;
    for &count in byte_count.iter() {
        if count != 0 {
            let symbol_probability = count as f32 / buf.len() as f32;
            entropy += symbol_probability * symbol_probability.log2();
        }
    }
    -entropy
}
