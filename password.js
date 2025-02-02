async function encrypt(text, password) {
	const keyParams = { iterations: 1000000, salt: crypto.getRandomValues(new Uint8Array(32)) };
	const derivedBits = await AES().generatePBKDF2(password, undefined, keyParams);
    const derivedKey = await AES().createGcmKey(derivedBits);			
	const iv = crypto.getRandomValues(new Uint8Array(12));		
	const encryptedText = AES().setKeyParams(keyParams, await AES().gcmEncrypt(text, derivedKey, iv));
	return encryptedText;
}

async function decrypt(encryptedText, password) {
	const oldKeyParams = AES().getKeyParams(encryptedText);
	const oldDerivedBits = await AES().generatePBKDF2(password, undefined, oldKeyParams);
	const oldDerivedKey = await AES().createGcmKey(oldDerivedBits);
	const text = await AES().gcmDecrypt(encryptedText, oldDerivedKey);
	return text;
}
