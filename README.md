# An implementation for secure data deduplication on end-to-end encrypted documents


## This project presents a solution for secure storage with the possibility of deduplication

To obtain more efficient solutions for data transfer and storage, data deduplication techniques were designed and implemented. Still, it was proved that those first schemes,
implemented by large companies, such as Dropbox, were
insecure and allowed for unauthorized data access. Since
then, many schemes for secure data deduplication have been
proposed.

From 2010 to the present day,
security properties for data deduplication were tackled mainly
using the following approaches:1. Convergent Encryption: Data is encrypted using a key derived from the data itself. This allows identical files to produce identical encrypted representations, making deduplication possible.

2. Proof of Ownership (PoW): Before allowing a user to access an existing stored file, the system verifies that the user actually possesses the original data. This helps prevent unauthorized users from claiming ownership of files they do not have.

3. Message-Locked Encryption: Encryption keys are deterministically generated from the message or file content. This enables identical data to share the same encrypted representation while maintaining confidentiality.

4. Secure Key Management: Encryption keys must be protected against unauthorized access. Secure key storage, controlled key distribution, and appropriate cryptographic practices are essential to protecting user data.

5. Access Control and Authentication: The system must verify user identities and enforce permissions before allowing files to be uploaded, retrieved, modified, or deleted.

6. Data Integrity Verification: Cryptographic hash functions can be used to verify that stored data has not been modified or corrupted during transmission or storage.

These approaches aim to achieve a balance between storage efficiency, data confidentiality, data integrity, and protection against unauthorized access.
- Proof of ownership .
- Message-dependent encryption.
- Traffic Obfuscation
- Deterministic information dispersal 

Alongside the above mentioned approaches, semantic secure
data deduplication schemes were proposed, but were
proven to be unusable from a user-experience perspective.
Most solutions to approach deduplication problem via Proof
of ownership are based on Merkle Hash Tree, which are
a good method to generate and check challenges regarding
data content. Although MHT seem to be a sensible approach
for this solution, MHT are I/O intensive, therefore are not as
efficient as one might wish. In our approach, the server stores a
set of precomputed challenges that are to be used when another
user would claim the ownership of the same document.

Message-dependant encryption started using a simple aproach to encrypt documents using a some information generated from the file content itself. This way, one may assure a
better deduplication factor, since two identical cleartext have
the same cyphertext. This proposals evolved over time by using
key servers and they also could generate a randomized tag, that
is used to identify the document.

To enhance data deduplication efficiency and security, we
propose using a proxy server as an intermediary between the
client and server. This approach expedites Proof of Ownership (PoW) computation, reducing client-side workload and
mitigating security risks from network monitoring attacks. By
acting as a protective barrier, the proxy server enhances overall
performance and security in the deduplication process.

## System diagram

![System_diagram](https://github.com/user-attachments/assets/80c746e7-0a36-4d3f-bf62-6eaae87b5038)