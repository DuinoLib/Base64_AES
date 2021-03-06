#include <ESP8266WiFi.h>
#include <Base64_AES.h>

byte *secret_key = (unsigned char*)"12345678123456781234567812345678";// it should be 16 or 32 letter
Base64_AES aes(256);


void setup() {
  // initialize both serial ports:
  Serial.begin(115200);
  aes.setkey(secret_key);
}

unsigned long milli = 0;
void loop() {
  if (millis() - milli > 2000) {
    milli=millis();
    Serial.print("Free Heap:");
    Serial.println(ESP.getFreeHeap());
  }
  if (Serial.available()) {
    String inputstr = Serial.readString();
    int inputLen = inputstr.length();
    char *input = new char[inputLen];
    inputstr.toCharArray(input, inputLen);

    /// Let's do encryption decryption

    Serial.println();
    unsigned long time1a = micros();
    int epected_encode_legth = aes.expected_encrypted_b64_len(inputLen);
    char *baseencoded = new char[epected_encode_legth];
    aes.encrypt_b64(input, inputLen, baseencoded);
    unsigned long time1b = micros();
    Serial.println("Encrypted: ");
    Serial.println(baseencoded);

    /////////////////////////////
    unsigned long time2a = micros();
    int epected_msg_len = aes.expected_decrypted_b64_len(epected_encode_legth);
    char *decryptedmsg = new char[epected_msg_len];
    aes.decrypt_b64(baseencoded, epected_encode_legth, decryptedmsg);
    unsigned long time2b = micros();
    Serial.println("Dencrypted: ");
    Serial.println(decryptedmsg);

    /////////////////////////////////
    unsigned long encrypt_time = time1b - time1a;
    Serial.print("Encryption duration(micros()): ");
    Serial.println(encrypt_time);

    unsigned long decrypt_time = time2b - time2a;
    Serial.print("Decryption duration(micros()): ");
    Serial.println(decrypt_time);
    delete decryptedmsg;
    delete baseencoded;
    delete input;
  }
}