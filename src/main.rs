use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes256Ctr;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let enc_file = &args[1];
    let key_file = &args[2];

    // https://github.com/TelegramOrg/Telegram-Android/blob/1eea3ab6f7fa8ff5b90282a2bb0e919aabea7d35/TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java#L737-L746
    let mut data = std::fs::read(enc_file)?;
    let mut key = std::fs::read(key_file)?;
    assert_eq!(key.len(), 48);

    let (key, nonce) = key.split_at_mut(32);

    // https://github.com/TelegramOrg/Telegram-Android/blob/1eea3ab6f7fa8ff5b90282a2bb0e919aabea7d35/TMessagesProj/src/main/java/org/telegram/messenger/FileLoadOperation.java#L1388-L1395
    /*
    int offset = requestInfo.offset / 16;
    encryptIv[15] = (byte) (offset & 0xff);
    encryptIv[14] = (byte) ((offset >> 8) & 0xff);
    encryptIv[13] = (byte) ((offset >> 16) & 0xff);
    encryptIv[12] = (byte) ((offset >> 24) & 0xff);
    Utilities.aesCtrDecryption(bytes.buffer, encryptKey, encryptIv, 0, bytes.limit());
    */
    // The offset is always 0 in my settings
    nonce[15] = 0;
    nonce[14] = 0;
    nonce[13] = 0;
    nonce[12] = 0;

    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let mut cipher = Aes256Ctr::new(&key, &nonce);

    cipher.apply_keystream(&mut data);

    std::fs::write("/tmp/x", data)
}
