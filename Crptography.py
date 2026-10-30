import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class CryptographyVehicleApp:
    def __init__(self):
        self.vehicles = {}

        # Generate an RSA key pair for this application session.
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    @staticmethod
    def sha256_hash():
        message = input("Enter a message to hash: ")
        digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
        print("\nSHA-256 hash:")
        print(digest)

    def digital_signature(self):
        message = input("Enter the message to sign: ")
        message_bytes = message.encode("utf-8")

        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("\nDigital signature (hex):")
        print(signature.hex())

        try:
            self.public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("\nSignature verification: VALID")
        except Exception:
            print("\nSignature verification: INVALID")

        test = input(
            "\nTest verification with a different message? (y/n): "
        ).strip().lower()

        if test == "y":
            modified_message = input("Enter the message to verify against: ")
            try:
                self.public_key.verify(
                    signature,
                    modified_message.encode("utf-8"),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Signature verification: VALID")
            except Exception:
                print("Signature verification: INVALID")

    def register_vehicle(self):
        number_plate = input("Enter vehicle number plate: ").strip().upper()
        owner = input("Enter owner name: ").strip()
        model = input("Enter vehicle model: ").strip()

        if not number_plate or not owner or not model:
            print("Error: Number plate, owner name, and model cannot be empty.")
            return

        if number_plate in self.vehicles:
            print("Error: This number plate is already registered.")
            return

        self.vehicles[number_plate] = {
            "owner": owner,
            "model": model
        }
        print(f"Vehicle {number_plate} registered successfully.")

    def retrieve_vehicle(self):
        number_plate = input("Enter vehicle number plate to search: ").strip().upper()

        if not number_plate:
            print("Error: Number plate cannot be empty.")
            return

        vehicle = self.vehicles.get(number_plate)
        if vehicle is None:
            print("Error: No vehicle found with that number plate.")
            return

        print("\nVehicle Details")
        print("----------------")
        print(f"Number Plate : {number_plate}")
        print(f"Owner        : {vehicle['owner']}")
        print(f"Model        : {vehicle['model']}")

    def show_public_key(self):
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        print("\nPublic key (PEM):")
        print(public_pem)
        print("The private key is not displayed.")

    def run(self):
        while True:
            print("\n===== CRYPTOGRAPHY AND VEHICLE REGISTRATION SYSTEM =====")
            print("1. Generate SHA-256 Hash")
            print("2. Create and Verify Digital Signature")
            print("3. Register Vehicle")
            print("4. Retrieve Vehicle Details")
            print("5. Display Public Key")
            print("6. Exit")

            choice = input("Enter your choice (1-6): ").strip()

            if choice == "1":
                self.sha256_hash()
            elif choice == "2":
                self.digital_signature()
            elif choice == "3":
                self.register_vehicle()
            elif choice == "4":
                self.retrieve_vehicle()
            elif choice == "5":
                self.show_public_key()
            elif choice == "6":
                print("Thank you for using the application.")
                break
            else:
                print("Invalid choice. Please enter a number from 1 to 6.")


if __name__ == "__main__":
    try:
        app = CryptographyVehicleApp()
        app.run()
    except ImportError:
        print("Missing dependency. Install it by running: pip install cryptography")
