# smbench
SmallBenchmark, ferramenta em C para benchmarks rápidos, procurando ser o mais low-level possível.

Um arquivo só.

## build

```sh
gcc -O2 -o bench bench.c -lm
```

## uso

```sh
# binário existente
./bench ./meu_programa arg1 arg2

# código fonte (compila e já roda)
./bench meu_programa.c
```

## o que mede

- **timing** - wall time, user time, sys time e overhead de sistema
- **cpu** - cycles, instructions, IPC, stall rate (requer bare metal; zerado em WSL/VM)
- **cache** - referências, misses e miss rate
- **branches** - total, mispredicted e miss rate
- **memory** - RSS máximo, heap peak, page faults, context switches
- **syscalls** - tabela com contagem, tempo total e tempo médio por chamada
- **score** - nota de 0 a 100 com grade (A/B/C/D/F)

## observação

Contadores de hardware (cycles, IPC, cache, branches) dependem de `perf_event_open` com acesso ao hardware real. Em WSL e a maioria das VMs esses valores ficam zerados, vou olhar mais nisso depois.
