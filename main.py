from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

# 1️⃣ 인증서 로드 (PEM 또는 DER 형식 지원)
def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

# 2️⃣ 서명된 원본 데이터 로드
def load_data(data_path):
    with open(data_path, "rb") as data_file:
        return data_file.read()

# 3️⃣ 서명값 로드 (바이너리 파일)
def load_signature(sig_path):
    with open(sig_path, "rb") as sig_file:
        return sig_file.read()

# 4️⃣ 서명 검증
def verify_signature(cert_path, data_path, sig_path):
    try:
        # 인증서, 데이터, 서명 불러오기
        cert = load_certificate(cert_path)
        data = load_data(data_path)
        signature = load_signature(sig_path)

        # 인증서에서 공개 키 추출
        public_key = cert.public_key()

        # 공개 키로 서명 검증 수행
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())  # ECDSA + SHA-256 사용
        )
        print("✅ 서명이 유효합니다!")
    except Exception as e:
        print(f"❌ 서명 검증 실패: {e}")

# 🛠 실행 예시 (파일 경로에 맞게 수정하세요)
verify_signature("certificate.pem", "data.txt", "signature.sig")
