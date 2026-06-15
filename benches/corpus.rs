#[path = "../tests/corpus_data.rs"]
mod corpus_data;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

struct Corpus {
    archives: Vec<(&'static str, Vec<u8>)>,
}

impl Corpus {
    fn load() -> Self {
        let archives = corpus_data::SEMBIANCE_FILES
            .iter()
            .map(|&name| {
                let path = corpus_data::download(name);
                let raw = std::fs::read(&path).expect("read corpus file");
                let data = unvise::macbinary::strip(raw);
                (name, data)
            })
            .collect();
        Self { archives }
    }
}

fn bench_parse(c: &mut Criterion) {
    let corpus = Corpus::load();
    let mut group = c.benchmark_group("parse");
    for (name, data) in &corpus.archives {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| unvise::Archive::parse(data.clone()));
        });
    }
    group.finish();
}

fn bench_decompress(c: &mut Criterion) {
    let corpus = Corpus::load();
    let mut group = c.benchmark_group("parse_and_decompress");
    for (name, data) in &corpus.archives {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| unvise::fuzzing::parse_and_decompress(data));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse, bench_decompress);
criterion_main!(benches);
