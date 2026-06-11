#  Docker file file for Rust Builder
FROM rust:latest

# Create user with UID 1000
RUN useradd -m -u 1000 appuser

# Add MUSL

RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /workspace

USER appuser

CMD ["bash"]