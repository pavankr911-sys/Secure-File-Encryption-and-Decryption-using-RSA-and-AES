"""
app.py
Main Flask application entry point for the CNS project:
"Secure File Encryption and Decryption System Using AES and RSA"
"""

import os
import io
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

import crypto_utils
import package_utils
from crypto_utils import (
    CryptoError,
    InvalidKeyError,
    AuthenticationError,
    DecryptionError,
)
from package_utils import (
    PackageError,
    PackageFormatError,
    CorruptedPackageError,
    SecurityLimitExceededError,
)


def create_app(test_config=None):
    app = Flask(__name__)
    
    # Secure defaults
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", os.urandom(24)),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16 MB max payload size for file operations
    )

    if test_config:
        app.config.update(test_config)

    @app.route("/", methods=["GET"])
    def index():
        """
        Renders the cybersecurity dashboard.
        """
        return render_template("index.html")

    @app.route("/health", methods=["GET"])
    def health_check():
        """
        Health-check endpoint returning the system status and crypto capabilities.
        """
        return jsonify({
            "status": "healthy",
            "service": "CNS File Encryption & Decryption System",
            "crypto_engine": "PyCryptodome",
            "algorithms": {
                "symmetric": "AES-256-GCM (Authenticated Encryption)",
                "asymmetric": "RSA-3072 with OAEP (SHA-256 / MGF1 padding)",
                "rng": "CSPRNG (get_random_bytes)"
            },
            "version": "1.0.0"
        }), 200

    @app.route("/api/keys/generate", methods=["POST"])
    def api_generate_keys():
        """
        Generates a fresh RSA key pair with configurable bit length.
        """
        try:
            data = request.get_json(silent=True) or {}
            key_size = int(data.get("key_size", crypto_utils.RSA_DEFAULT_KEY_SIZE))
            
            if key_size not in (2048, 3072, 4096):
                return jsonify({
                    "error": "Invalid key size. Allowed sizes are 2048, 3072, or 4096 bits."
                }), 400

            private_pem, public_pem = crypto_utils.generate_rsa_key_pair(bits=key_size)
            
            return jsonify({
                "success": True,
                "key_size": key_size,
                "public_key": public_pem,
                "private_key": private_pem,
            }), 200

        except InvalidKeyError as err:
            return jsonify({"error": str(err)}), 400
        except Exception as err:
            return jsonify({"error": "Failed to generate RSA key pair."}), 500

    @app.route("/api/encrypt", methods=["POST"])
    def api_encrypt_file():
        """
        Encrypts an uploaded file using AES-256-GCM and wraps the key using RSA-OAEP.
        Returns the .sfe package file download.
        """
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded for encryption."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"error": "Selected file is empty or invalid."}), 400

        # Retrieve public key (either from separate text field or uploaded public key file)
        public_key_pem = request.form.get("public_key", "").strip()
        if "public_key_file" in request.files and request.files["public_key_file"].filename:
            public_key_pem = request.files["public_key_file"].read().decode("utf-8", errors="replace").strip()

        if not public_key_pem:
            return jsonify({"error": "Recipient RSA public key is required for encryption."}), 400

        try:
            file_bytes = uploaded_file.read()
            original_filename = secure_filename(uploaded_file.filename) or "encrypted_file.bin"

            # Encrypt and package directly into .sfe
            sfe_package_bytes = package_utils.encrypt_file_to_sfe_package(
                file_bytes=file_bytes,
                filename=original_filename,
                recipient_public_key=public_key_pem
            )

            download_filename = f"{os.path.splitext(original_filename)[0]}.sfe"

            return send_file(
                io.BytesIO(sfe_package_bytes),
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name=download_filename
            )

        except (InvalidKeyError, PackageFormatError) as err:
            return jsonify({"error": str(err)}), 400
        except SecurityLimitExceededError as err:
            return jsonify({"error": str(err)}), 413
        except CryptoError as err:
            return jsonify({"error": str(err)}), 400
        except Exception as err:
            return jsonify({"error": "Encryption failed due to an internal server error."}), 500

    @app.route("/api/decrypt", methods=["POST"])
    def api_decrypt_file():
        """
        Unwraps session key and decrypts an uploaded .sfe package using the recipient's private key.
        Returns the original decrypted file download.
        """
        if "file" not in request.files:
            return jsonify({"error": "No .sfe package uploaded for decryption."}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file or uploaded_file.filename == "":
            return jsonify({"error": "Selected .sfe file is empty or invalid."}), 400

        # Retrieve private key
        private_key_pem = request.form.get("private_key", "").strip()
        if "private_key_file" in request.files and request.files["private_key_file"].filename:
            private_key_pem = request.files["private_key_file"].read().decode("utf-8", errors="replace").strip()

        if not private_key_pem:
            return jsonify({"error": "Recipient RSA private key is required for decryption."}), 400

        passphrase = request.form.get("passphrase", "").strip() or None

        try:
            package_bytes = uploaded_file.read()

            decrypted_bytes, manifest = package_utils.decrypt_file_from_sfe_package(
                package_bytes=package_bytes,
                recipient_private_key=private_key_pem,
                passphrase=passphrase
            )

            original_filename = manifest.get("file_metadata", {}).get(
                "original_filename", "decrypted_file.bin"
            )

            response = send_file(
                io.BytesIO(decrypted_bytes),
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name=original_filename
            )
            # Expose original filename header so frontend fetch can capture it
            response.headers["X-Decrypted-Filename"] = original_filename
            response.headers["Access-Control-Expose-Headers"] = "X-Decrypted-Filename"
            return response

        except AuthenticationError:
            return jsonify({
                "error": "Authentication failed: The encrypted file has been tampered with or corrupted."
            }), 400
        except DecryptionError:
            return jsonify({
                "error": "Decryption failed: Incorrect RSA private key or corrupted key payload."
            }), 400
        except (InvalidKeyError, PackageFormatError, CorruptedPackageError) as err:
            return jsonify({"error": str(err)}), 400
        except SecurityLimitExceededError as err:
            return jsonify({"error": str(err)}), 413
        except Exception as err:
            return jsonify({"error": "Decryption failed due to an internal server error."}), 500

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File size exceeds the 16MB limit"}), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({"error": "Internal server error"}), 500

    return app


app = create_app()

if __name__ == "__main__":
    # Run development server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
