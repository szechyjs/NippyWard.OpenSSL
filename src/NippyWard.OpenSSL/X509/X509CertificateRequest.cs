using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Buffers;

using NippyWard.OpenSSL.ASN1;
using NippyWard.OpenSSL.Interop;
using NippyWard.OpenSSL.Interop.SafeHandles;
using NippyWard.OpenSSL.Interop.SafeHandles.Crypto;
using NippyWard.OpenSSL.Interop.SafeHandles.X509;
using NippyWard.OpenSSL.Keys;
using NippyWard.OpenSSL.Collections;

namespace NippyWard.OpenSSL.X509
{
    public class X509CertificateRequest
        : X509CertificateBase,
            ISafeHandleWrapper<SafeX509RequestHandle>
    {
        SafeX509RequestHandle ISafeHandleWrapper<SafeX509RequestHandle>.Handle
            => this._Handle;
        public override SafeHandle Handle
            => this._Handle;

        public override int Version
        {
            get => (int)CryptoWrapper.X509_REQ_get_version(this._Handle);
            set => CryptoWrapper.X509_REQ_set_version(this._Handle, value);
        }

        internal readonly SafeX509RequestHandle _Handle;

        internal X509CertificateRequest(SafeX509RequestHandle requestHandle)
            : base()
        {
            this._Handle = requestHandle;
        }

        //only use for CA?
        internal X509CertificateRequest(SafeX509RequestHandle x509RequestHandle, SafeKeyHandle keyHandle)
            : this(x509RequestHandle)
        {
            this.SetPublicKey(PrivateKey.GetCorrectKey(keyHandle));
        }

        public X509CertificateRequest(int bits)
            : this(Create509Request(CryptoWrapper.X509_REQ_new(), bits))
        {
            this.Version = 2;
        }

        public X509CertificateRequest(int bits, string OU, string CN)
            : this(bits)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        public X509CertificateRequest(PrivateKey privateKey)
            : this(Create509Request(CryptoWrapper.X509_REQ_new(), privateKey))
        {
            this.Version = 0;
        }

        public X509CertificateRequest(PrivateKey privateKey, string OU, string CN)
            : this(privateKey)
        {
            this.OrganizationUnit = OU;
            this.Common = CN;
        }

        private static SafeX509RequestHandle Create509Request(SafeX509RequestHandle handle, int bits)
        {
            using (RSAKey key = new RSAKey(bits))
            {
                return Create509Request(handle, key);
            }
        }

        private static SafeX509RequestHandle Create509Request(SafeX509RequestHandle handle, PrivateKey key)
        {
            CryptoWrapper.X509_REQ_set_pubkey(handle, key._Handle);
            return handle;
        }

        public override bool VerifyPrivateKey(PrivateKey key)
        {
            return CryptoWrapper.X509_REQ_check_private_key(this._Handle, key._Handle) == 1;
        }

        public override bool VerifyPublicKey(IPublicKey key)
        {
            return CryptoWrapper.X509_REQ_verify(this._Handle, ((Key)key)._Handle) == 1;
        }

        internal override PrivateKey GetPublicKey()
        {
            return PrivateKey.GetCorrectKey(CryptoWrapper.X509_REQ_get0_pubkey(this._Handle));
        }

        internal override SafeX509NameHandle GetSubject()
        {
            return CryptoWrapper.X509_REQ_get_subject_name(this._Handle);
        }

        internal override void SetPublicKey(PrivateKey privateKey)
        {
            CryptoWrapper.X509_REQ_set_pubkey(this._Handle, privateKey._Handle);
        }

        internal override void Sign(SafeKeyHandle keyHandle, SafeMessageDigestHandle md)
        {
            CryptoWrapper.X509_REQ_sign(this._Handle, keyHandle, md);
        }

        public static X509CertificateRequest Read(string filePath, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"The file {filePath} has not been found");

            ReadOnlySpan<char> strPath = Path.GetFullPath(filePath).AsSpan();
            ReadOnlySpan<byte> readonlySpan = new Span<byte>(Native.ReadOnly);

            using (FileStream stream = new FileStream(filePath, FileMode.Open))
                return Read(stream, password, fileEncoding);
        }

        public static X509CertificateRequest Read(Stream stream, string password, FileEncoding fileEncoding = FileEncoding.PEM)
        {
            if (!stream.CanRead)
                throw new InvalidOperationException("Stream is not readable");

            byte[] buf = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                int read;
                using (SafeBioHandle bio = Native.CryptoWrapper.BIO_new(Native.CryptoWrapper.BIO_s_mem()))
                {
                    Span<byte> bufSpan = new Span<byte>(buf);
                    while ((read = stream.Read(buf, 0, buf.Length)) > 0)
                    {
                        Native.CryptoWrapper.BIO_write(bio, bufSpan.GetPinnableReference(), read);
                        Array.Clear(buf, 0, read);
                    }

                    return ReadCertificate(bio, password, fileEncoding);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static X509CertificateRequest ReadCertificate(SafeBioHandle bioHandle, string password, FileEncoding fileEncoding)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                return new X509CertificateRequest(Native.CryptoWrapper.PEM_read_bio_X509_REQ(bioHandle, IntPtr.Zero, pass.Callback, IntPtr.Zero));
            else if (fileEncoding == FileEncoding.DER)
                return new X509CertificateRequest(Native.CryptoWrapper.d2i_X509_REQ_bio(bioHandle, IntPtr.Zero));

            throw new FormatException("Encoding not supported");
        }

        internal override void WriteCertificate(SafeBioHandle bioHandle, string password, CipherType cipherType, FileEncoding fileEncoding)
        {
            PasswordCallback callBack = new PasswordCallback(password);
            PasswordThunk pass = new PasswordThunk(callBack.OnPassword);

            if (fileEncoding == FileEncoding.PEM)
                CryptoWrapper.PEM_write_bio_X509_REQ(bioHandle, this._Handle);
            else if (fileEncoding == FileEncoding.DER)
                CryptoWrapper.i2d_X509_REQ_bio(bioHandle, this._Handle);
            else
                throw new FormatException("Encoding not supported");
        }
    }
}
