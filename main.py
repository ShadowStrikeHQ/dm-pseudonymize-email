import hashlib
import argparse
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Pseudonymize email addresses in a dataset.")
    parser.add_argument("email", help="The email address to pseudonymize.")
    parser.add_argument("--secret_key", required=True, help="A secret key used to generate the pseudonym. Keep this safe!")
    parser.add_argument("--domain", default="example.com", help="The domain to use for the pseudonymized email address. Defaults to example.com.")
    parser.add_argument("--algorithm", default="sha256", choices=['sha256', 'sha512', 'md5'], help="Hashing algorithm to use. Defaults to sha256.  sha256/512 are stronger, MD5 is faster.")
    parser.add_argument("--salt", default="", help="Salt to add to the email address before hashing. Improves security.")
    parser.add_argument("--output", default="stdout", choices=['stdout','stderr','file'], help="Where to print the output, defaults to stdout.")
    parser.add_argument("--output_file", default="pseudonymized_emails.txt", help="The file path where to store pseudonymized emails, only if output is set to file.  Defaults to pseudonymized_emails.txt.")

    return parser

def pseudonymize_email(email, secret_key, domain="example.com", algorithm="sha256", salt=""):
    """
    Replaces an email address with a consistent, but fake, email address.

    Args:
        email (str): The email address to pseudonymize.
        secret_key (str): A secret key used to generate the pseudonym.
        domain (str, optional): The domain to use for the pseudonymized email address. Defaults to "example.com".
        algorithm (str, optional): Hashing algorithm to use. Defaults to "sha256".
        salt (str, optional): Salt to add to the email address before hashing. Defaults to "".

    Returns:
        str: The pseudonymized email address.
    """
    if not isinstance(email, str) or not email:
        raise ValueError("Email must be a non-empty string.")
    if not isinstance(secret_key, str) or not secret_key:
        raise ValueError("Secret key must be a non-empty string.")
    if not isinstance(domain, str) or not domain:
        raise ValueError("Domain must be a non-empty string.")

    try:
        # Sanitize input to prevent injection attacks (e.g., if used in SQL queries later)
        email = email.strip()
        secret_key = secret_key.strip()
        domain = domain.strip()
        salt = salt.strip()

        # Combine email, salt, and secret key for hashing
        combined_string = email + salt + secret_key

        # Choose hashing algorithm
        if algorithm == "sha256":
            hashed_email = hashlib.sha256(combined_string.encode('utf-8')).hexdigest()
        elif algorithm == "sha512":
            hashed_email = hashlib.sha512(combined_string.encode('utf-8')).hexdigest()
        elif algorithm == "md5":
            hashed_email = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
        else:
            raise ValueError("Invalid hashing algorithm specified.")

        # Create the pseudonymized email address
        pseudonymized_email = f"{hashed_email[:16]}@{domain}" # use first 16 charaters of the hash to create a valid name.
        return pseudonymized_email

    except Exception as e:
        logging.error(f"Error pseudonymizing email: {e}")
        raise

def main():
    """
    Main function to parse arguments and pseudonymize email addresses.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        pseudonymized_email = pseudonymize_email(args.email, args.secret_key, args.domain, args.algorithm, args.salt)

        if args.output == "stdout":
             print(pseudonymized_email)
        elif args.output == "stderr":
            print(pseudonymized_email, file=sys.stderr)
        elif args.output == "file":
            try:
                with open(args.output_file, "a") as f:
                    f.write(pseudonymized_email + "\n")  # Append the pseudonymized email to the file
                logging.info(f"Pseudonymized email written to {args.output_file}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
                print(f"Error writing to file: {e}", file=sys.stderr)  # Print error to stderr as well
                sys.exit(1)
        else:
             print(pseudonymized_email)  #Defaults to stdout
    except ValueError as e:
        logging.error(f"Input error: {e}")
        print(f"Error: {e}", file=sys.stderr) # print to stderr
        sys.exit(1) # Exit with non-zero exit code for error.
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Example usage:
    # python main.py test@example.com --secret_key mysecret --domain mydomain.com
    # python main.py test@example.com --secret_key mysecret --algorithm md5
    # python main.py test@example.com --secret_key mysecret --salt mysalt
    # python main.py test@example.com --secret_key mysecret --output file --output_file output.txt

    main()