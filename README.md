# NippyWard.OpenSSL
A multi-platform OpenSSL .NET wrapper containing a high-performance TLS implementation

## Rationale
I was writing some networking code, but the SSL connection would not succeed. This only occured on Windows. On Linux - mono only at the time - the SSL connection always succeeded. Hence I needed an OpenSSL wrapper and stumbled upon https://github.com/openssl-net/openssl-net. This project was already abandoned, but it still ran fine on .NET framwork/mono. After .NET Core came out I kept everything compatible and also started refactoring the code. It has now evovled into a mostly X509/TLS wrapper.

## Installation
### Linux
Ensure OpenSSL is installed! This should be the default for most if not all distributions. At the time of writing NippyWard.OpenSSL supports ubuntu.16.04-upwards and Debian-8-upwards.

Any other distribution can be added in https://github.com/sebaFlame/NippyWard.OpenSSL/blob/dea1127c40566a918796059a4d48c322d5e9329a/src/NippyWard.OpenSSL/Interop/Native.cs#L79-L102, but most should Just Work™.

### Windows
Create and install a NuGet package from [runtime.win.OpenSSL](deps/runtime.win.OpenSSL/).

Building this package downloads the required DLL files (x86 & x64) from http://wiki.overbyte.eu, who provide signed builds of the latest OpenSSL.

Nuget push pushes the NuGet package to your local cache. This way it can be consumed by any project.

```cmd
cd deps\NippyWard.OpenSSL.Tasks
dotnet build
cd ..\runtime.win.OpenSSL
dotnet build
dotnet pack
dotnet nuget push bin\Debug\runtime.win.OpenSSL.1.1.1n.nupkg -s %USERPROFILE%\.nuget\packages
```
This nuget package should get auto-referenced when on Windows and referencing NippyWard.OpenSSL. You need to guarantee it's in your cache, because it is not available on NuGet.org.

### MacOS
Copy (or symlink) `libssl.3.dylib` and `libcrypto.3.dylib` to your bin directory. These libraries can be found in the OpenSSL installation directory,
which is usually `/opt/homebrew/opt/openssl@3/lib` if you installed OpenSSL using Homebrew.

## Usage
See [tests](test/NippyWard.OpenSSL.Tests) for usage examples.

### Encryption
```C#
byte[] iv = Encoding.ASCII.GetBytes("12345678"); //initialization vector is 8 bytes
byte[] key = Encoding.ASCII.GetBytes("This is the key"); //best practice ia a key of 16 bytes or more

Span<byte> inputSpan; //data to encrypt
Span<byte> outputSpan; //data to decrypt

//initialize an encryption context
using (CipherEncryption cipherEncryption = new CipherEncryption(CipherType.AES_256_CBC, key, iv))
{
    //you can keep updating as long as there is more data to encrypt
    int encryptedLength = cipherEncryption.Update(inputSpan, ref outputSpan);

    //when all data has been encrypted, finalize to encrypt the trailing bytes
    int finalEncryptedLength = cipherEncryption.Finalize(ref outputSpan);
}
```

Decryption is the same. See [TestCipher](test/NippyWard.OpenSSL.Tests/TestCipher.cs) for further details.

### Hashing
```C#
Span<byte> inputSpan; //data to hash

//create an SHA156 hash
using (Digest ctx = new Digest(DigestType.SHA256))
{
    //you can keep updating as long as there is more data to hash
    ctx.Update(inputSpan);

    //when all data has been hashed, finalize to hash trailing bytes
    //and receive the hash
    //a hash has a fixed length
    ctx.Finalize(out Span<byte> outputSpan);
}
```

### Keys
```C#
Span<byte> unencrypted; //the data to encrypt

//create a 1024 bit RSA key
using (RSAKey key = new RSAKey(1024))
{
    //and encrypt some data using the key
    using (KeyContext keyContext = key.CreateEncryptionContext())
    {
        //get size of encrypted buffer
        encryptedLength = key.EncryptedLength(in keyContext, unencrypted);

        //create buffer to store encrypted data
        Span<byte> encrypted = new Span<byte>(new byte[encryptedLength]);

        //encrypt data
        key.Encrypt(in keyContext, unencrypted, encrypted, out encryptedLength);
    }
}
```
Decryption is the same. See [TestKey](test/NippyWard.OpenSSL.Tests/TestKey.cs) for further details.

### X509
```C#
DateTime start = DateTime.Now;
DateTime end = start + TimeSpan.FromMinutes(10);

//create a key to use in the certificate
using (RSAKey key = new RSAKey(2048))
{
    //create a new certificate
    using (X509Certificate cert = new X509Certificate(key, "localhost", "localhost", start, end))
    {
        //add some extensions concerning certificate usage
        cert.AddX509Extension(X509ExtensionType.BasicConstraints,  "CA:true");
        cert.AddX509Extension(X509ExtensionType.KeyUsage, "cRLSign,keyCertSign");

        //self-sign the certificate and generate a public key
        cert.SelfSign(key, DigestType.SHA256);

        //use the certificate
    }
}
```
There are also several extension and CA examples in [TestX509Certificate](test/NippyWard.OpenSSL.Tests/TestX509Certificate.cs).

### TLS
The TLS implementation is to be used as an API and should not be consumed directly. See [NippyWard.Networking.Tls](https://github.com/sebaFlame/NippyWard.Networking/tree/master/src/NippyWard.Networking.Tls) for an asynchronous client/server implementation of the API.
