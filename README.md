# HD Wallet Lab

บทเรียนแบบโต้ตอบสำหรับการเรียนรู้กลไกภายในของ Hierarchical Deterministic (HD) Wallet ตั้งแต่การสร้าง Entropy ไปจนถึงการหาเลขที่อยู่ (Address) ของ Bitcoin

โครงการนี้สร้างขึ้นเพื่อให้ผู้ใช้เข้าใจขั้นตอนทางคริปโตกราฟีอย่างละเอียด เช่น BIP39 (Mnemonic), BIP32/BIP44/BIP84 (Derivation Paths) และการคำนวณ Hash ต่างๆ ผ่านการลงมือทำจริงด้วยเครื่องมือในตัว

ผลงานนี้เป็นส่วนหนึ่งของการทดลองแบบ **Vibe Coding**

## คุณสมบัติหลัก
- การสร้างความสุ่ม (Entropy) และการเปลี่ยนเป็น Mnemonic 12 คำ
- การคำนวณ Seed จาก Mnemonic และ Passphrase
- การหา Master Key และการสืบทอดกุญแจลูก (Child Key Derivation)
- การคำนวณกุญแจสาธารณะ (Public Key) และที่อยู่แบบ Native SegWit/Taproot
- **xpub Mode**: โหมดขั้นสูงสำหรับการฝึกคำนวณ Extended Public Keys แบบแมนนวล
- **Toolbox Decoders**: เครื่องมือแกะรหัส Base58 และ Bech32/m เพื่อตรวจสอบโครงสร้างข้อมูล
- เครื่องมือคำนวณคริปโตกราฟีในตัว (SHA-256, RIPEMD-160, HMAC-SHA512 ฯลฯ)

## วิธีการใช้งาน
1. ติดตั้ง dependencies: `npm install`
2. รันโปรเจคในโหมดพัฒนา: `npm run dev`
3. สร้าง production build: `npm run build`

---

An interactive laboratory for learning the internal mechanics of Hierarchical Deterministic (HD) Wallets, from generating Entropy to deriving Bitcoin addresses.

This project is designed to help users understand cryptographic processes in detail, including BIP39 (Mnemonic), BIP32/BIP44/BIP84 (Derivation Paths), and various hash calculations through hands-on experience using built-in tools.

This project is a product of **Vibe Coding** experimentation.

## Key Features
- Entropy generation and mapping to 12-word Mnemonics
- Seed derivation from Mnemonics and Passphrases
- Master Key generation and Child Key Derivation
- Public Key calculation and Native SegWit/Taproot address derivation
- **xpub Mode**: Advanced mode for practicing manual Extended Public Key calculations
- **Toolbox Decoders**: Base58 and Bech32/m decoding tools for data structure inspection
- Built-in cryptographic tools (SHA-256, RIPEMD-160, HMAC-SHA512, etc.)

## How to Run
1. Install dependencies: `npm install`
2. Run development server: `npm run dev`
3. Create production build: `npm run build`

## License
MIT
