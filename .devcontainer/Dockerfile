FROM docker.io/scylladb/scylla-toolchain:fedora-42-20250630

USER root

RUN dnf install -y clangd procps-ng cgdb htop tcpdump && dnf clean all

RUN dnf debuginfo-install -y \
    boost \
    which \
    vim \
    c-ares \
    cryptopp \
    cyrus-sasl-lib \
    fmt \
    glibc \
    gnutls \
    hwloc-libs \
    jsoncpp \
    libevent \
    libffi \
    libicu \
    libidn2 \
    lksctp-tools \
    lua-libs \
    lz4-libs \
    nettle \
    openldap \
    openssl-libs \
    p11-kit \
    protobuf \
    snappy \
    systemd-libs \
    libtasn1 \
    liburing \
    libunistring \
    libxcrypt \
    libstdc++ \
    yaml-cpp \
    libcap \
    zlib  \
    libatomic \
    gmp \
    xxhash-libs \
    libdeflate && \
    dnf clean all

# Add gdbinit configuration for ScyllaDB debugging
RUN <<EOF cat > /root/.gdbinit
source /workspaces/scylladb/scylla-gdb.py
handle SIG35 noprint nostop
set debuginfod enabled on

define rscylla
    run --smp 1 --developer-mode 1 --vector-store-uri http://127.0.0.1:6080
end
document rscylla
    Runs the Scylla binary with --smp 1 and --developer-mode 1.
end
EOF

# --- Rust Installation ---
# Install rustup (the Rust toolchain manager)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN adduser karolnowacki
RUN sudo chown -R karolnowacki:karolnowacki /var
RUN pip install setuptools_scm pytest-timeout

# Add the Rust toolchain to the system's PATH
ENV PATH="/root/.cargo/bin:${PATH}"
# --- End of Rust Installation ---
