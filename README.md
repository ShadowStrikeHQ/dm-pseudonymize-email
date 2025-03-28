# dm-pseudonymize-email
Replaces email addresses in a dataset with consistent, but fake, email addresses to preserve uniqueness without revealing actual addresses. Uses a deterministic hash based on the original email and a secret key. - Focused on Tools designed to generate or mask sensitive data with realistic-looking but meaningless values

## Install
`git clone https://github.com/ShadowStrikeHQ/dm-pseudonymize-email`

## Usage
`./dm-pseudonymize-email [params]`

## Parameters
- `-h`: Show help message and exit
- `--secret_key`: A secret key used to generate the pseudonym. Keep this safe!
- `--domain`: The domain to use for the pseudonymized email address. Defaults to example.com.
- `--algorithm`: Hashing algorithm to use. Defaults to sha256.  sha256/512 are stronger, MD5 is faster.
- `--salt`: Salt to add to the email address before hashing. Improves security.
- `--output`: Where to print the output, defaults to stdout.
- `--output_file`: The file path where to store pseudonymized emails, only if output is set to file.  Defaults to pseudonymized_emails.txt.

## License
Copyright (c) ShadowStrikeHQ
