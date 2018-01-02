using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs12Store
    {
        internal Hashtable keys = new Hashtable();
        internal Hashtable localIds = new Hashtable();
        internal Hashtable certs = new Hashtable();
        internal Hashtable chainCerts = new Hashtable();
        internal Hashtable keyCerts = new Hashtable();

        internal DerObjectIdentifier  keyAlgorithm = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        internal DerObjectIdentifier  certAlgorithm = PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc;
        internal int                  minIterations = 1024;
        internal int                  saltSize = 20;

		internal class CertId
        {
            private readonly byte[] id;

            internal CertId(
                AsymmetricKeyParameter key)
            {
                this.id = new SubjectKeyIdentifier(
					SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key)).GetKeyIdentifier();
            }

            internal CertId(
                byte[] id)
            {
                this.id = id;
            }

            public override int GetHashCode()
            {
				return Arrays.GetHashCode(id);
            }

			public override bool Equals(
                object obj)
            {
				if (obj == this)
					return true;

				CertId other = obj as CertId;

				if (other == null)
                    return false;

				return Arrays.AreEqual(id, other.id);
            }
        }

		internal Asn1Sequence DecryptData(
            AlgorithmIdentifier	algId,
            byte[]				data,
            char[]				password,
			bool				wrongPkcs12Zero)
        {
            Pkcs12PbeParams pbeParams = Pkcs12PbeParams.GetInstance(algId.Parameters);
            ICipherParameters keyParameters = PbeUtilities.GenerateCipherParameters(
				algId.ObjectID, password, wrongPkcs12Zero, pbeParams);

			IBufferedCipher cipher = PbeUtilities.CreateEngine(algId.ObjectID) as IBufferedCipher;

			if (cipher == null)
			{
				// TODO Throw exception?
			}

			cipher.Init(false, keyParameters);

			byte[] encoding = cipher.DoFinal(data);

			return (Asn1Sequence) Asn1Object.FromByteArray(encoding);
        }

		internal byte[] EncryptData(
            AlgorithmIdentifier	algId,
            byte[]				data,
            char[]				password)
        {
            Pkcs12PbeParams pbeParams = Pkcs12PbeParams.GetInstance(algId.Parameters);
            ICipherParameters keyParameters = PbeUtilities.GenerateCipherParameters(
				algId.ObjectID, password, pbeParams);

			IBufferedCipher cipher = PbeUtilities.CreateEngine(algId.ObjectID) as IBufferedCipher;

			if (cipher == null)
			{
				// TODO Throw exception?
			}

			cipher.Init(true, keyParameters);

			return cipher.DoFinal(data);
        }

		public Pkcs12Store()
        {
        }

        public Pkcs12Store(
            Stream	input,
            char[]	password)
        {
			if (input == null)
			    throw new ArgumentNullException("input");
			if (password == null)
			    throw new ArgumentNullException("password");

			Asn1InputStream bIn = new Asn1InputStream(input);
			Asn1Sequence obj = (Asn1Sequence) bIn.ReadObject();
            Pfx bag = new Pfx(obj);
            ContentInfo info = bag.AuthSafe;
            ArrayList chain = new ArrayList();
            bool unmarkedKey = false;
			bool wrongPkcs12Zero = false;

            if (bag.MacData != null)           // check the mac code
            {
                MacData mData = bag.MacData;
                DigestInfo dInfo = mData.Mac;
                AlgorithmIdentifier algId = dInfo.AlgorithmID;
                byte[] salt = mData.GetSalt();
                int itCount = mData.IterationCount.IntValue;

				byte[] data = ((Asn1OctetString) info.Content).GetOctets();

				Asn1Encodable parameters = PbeUtilities.GenerateAlgorithmParameters(
					algId.ObjectID, salt, itCount);
                ICipherParameters keyParameters = PbeUtilities.GenerateCipherParameters(
					algId.ObjectID, password, parameters);
                IMac mac = (IMac)PbeUtilities.CreateEngine(algId.ObjectID);

                mac.Init(keyParameters);

                mac.BlockUpdate(data, 0, data.Length);

				byte[] res = new byte[mac.GetMacSize()];
                mac.DoFinal(res, 0);

				byte[] dig = dInfo.GetDigest();

				if (!Arrays.AreEqual(res, dig))
				{
					if (password.Length > 0)
					{
						throw new Exception("Pkcs12 key store mac invalid - wrong password or corrupted file.");
					}

					//
					// may be incorrect zero length password
					//
					keyParameters = PbeUtilities.GenerateCipherParameters(
						algId.ObjectID, password, true, parameters);

					mac.Init(keyParameters);

					mac.BlockUpdate(data, 0, data.Length);

					res = new byte[mac.GetMacSize()];
					mac.DoFinal(res, 0);

					if (!Arrays.AreEqual(res, dig))
					{
						throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file.");
					}

					wrongPkcs12Zero = true;
				}
			}

            keys = new Hashtable();
            localIds = new Hashtable();

            if (info.ContentType.Equals(PkcsObjectIdentifiers.Data))
            {
				byte[] octs = ((Asn1OctetString)info.Content).GetOctets();
				AuthenticatedSafe authSafe = new AuthenticatedSafe(
					(Asn1Sequence) Asn1OctetString.FromByteArray(octs));
                ContentInfo[] c = authSafe.GetContentInfo();

				for (int i = 0; i != c.Length; i++)
                {
                    if (c[i].ContentType.Equals(PkcsObjectIdentifiers.Data))
                    {
						byte[] octets = ((Asn1OctetString)c[i].Content).GetOctets();
                        Asn1Sequence seq = (Asn1Sequence) Asn1Object.FromByteArray(octets);

						for (int j = 0; j != seq.Count; j++)
                        {
                            SafeBag b = new SafeBag((Asn1Sequence) seq[j]);
                            if (b.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
                            {
                                EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.GetInstance(b.BagValue);
                                PrivateKeyInfo privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
									password, wrongPkcs12Zero, eIn);
                                AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privInfo);

                                //
                                // set the attributes on the key
                                //
                                Hashtable attributes = new Hashtable();
                                AsymmetricKeyEntry pkcs12Key = new AsymmetricKeyEntry(privKey, attributes);
                                string alias = null;
                                Asn1OctetString localId = null;

                                if (b.BagAttributes != null)
                                {
									foreach (Asn1Sequence sq in b.BagAttributes)
									{
                                        DerObjectIdentifier aOid = (DerObjectIdentifier) sq[0];
                                        Asn1Set attrSet = (Asn1Set) sq[1];
                                        Asn1Encodable attr = null;

										if (attrSet.Count > 0)
                                        {
                                            attr = attrSet[0];

                                            attributes.Add(aOid.Id, attr);
                                        }

                                        if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                                        {
                                            alias = ((DerBmpString)attr).GetString();
                                            keys[alias] = pkcs12Key;
                                        }
                                        else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                                        {
                                            localId = (Asn1OctetString)attr;
                                        }
                                    }
                                }

                                if (localId != null)
                                {
                                    string name = Encoding.ASCII.GetString(Hex.Encode(localId.GetOctets()));

                                    if (alias == null)
                                    {
                                        keys[name] = pkcs12Key;
                                    }
                                    else
                                    {
                                        localIds[alias] = name;
                                    }
                                }
                                else
                                {
                                    unmarkedKey = true;
                                    keys["unmarked"] = pkcs12Key;
                                }
                            }
                            else if (b.BagID.Equals(PkcsObjectIdentifiers.CertBag))
                            {
                                chain.Add(b);
                            }
                            else
                            {
                                Console.WriteLine("extra " + b.BagID);
                                Console.WriteLine("extra " + Asn1Dump.DumpAsString(b));
                            }
                        }
                    }
                    else if (c[i].ContentType.Equals(PkcsObjectIdentifiers.EncryptedData))
                    {
						EncryptedData d = EncryptedData.GetInstance(c[i].Content);
                        Asn1Sequence seq = DecryptData(d.EncryptionAlgorithm, d.Content.GetOctets(), password, wrongPkcs12Zero);

                        for (int j = 0; j != seq.Count; j++)
                        {
                            SafeBag b = new SafeBag((Asn1Sequence) seq[j]);

                            if (b.BagID.Equals(PkcsObjectIdentifiers.CertBag))
                            {
                                chain.Add(b);
                            }
                            else if (b.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
                            {
                                EncryptedPrivateKeyInfo eIn = EncryptedPrivateKeyInfo.GetInstance(b.BagValue);
                                PrivateKeyInfo privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
									password, wrongPkcs12Zero, eIn);
                                AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privInfo);

								//
                                // set the attributes on the key
                                //
                                Hashtable attributes = new Hashtable();
                                AsymmetricKeyEntry pkcs12Key = new AsymmetricKeyEntry(privKey, attributes);
                                string alias = null;
                                Asn1OctetString localId = null;

								foreach (Asn1Sequence sq in b.BagAttributes)
								{
                                    DerObjectIdentifier aOid = (DerObjectIdentifier) sq[0];
                                    Asn1Set attrSet = (Asn1Set) sq[1];
                                    Asn1Encodable attr = null;

                                    if (attrSet.Count > 0)
                                    {
                                        attr = attrSet[0];

                                        attributes.Add(aOid.Id, attr);
                                    }

                                    if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                                    {
                                        alias = ((DerBmpString)attr).GetString();
                                        keys[alias] = pkcs12Key;
                                    }
                                    else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                                    {
                                        localId = (Asn1OctetString)attr;
                                    }
                                }

                                string name = Encoding.ASCII.GetString(Hex.Encode(localId.GetOctets()));

                                if (alias == null)
                                {
                                    keys[name] = pkcs12Key;
                                }
                                else
                                {
                                    localIds[alias] = name;
                                }
                            }
                            else if (b.BagID.Equals(PkcsObjectIdentifiers.KeyBag))
                            {
                                PrivateKeyInfo privKeyInfo = PrivateKeyInfo.GetInstance(b.BagValue);
                                AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privKeyInfo);

                                //
                                // set the attributes on the key
                                //
                                string alias = null;
                                Asn1OctetString localId = null;
                                Hashtable attributes = new Hashtable();
                                AsymmetricKeyEntry pkcs12Key = new AsymmetricKeyEntry(privKey, attributes);

								foreach (Asn1Sequence sq in b.BagAttributes)
								{
                                    DerObjectIdentifier aOid = (DerObjectIdentifier) sq[0];
                                    Asn1Set attrSet = (Asn1Set) sq[1];
                                    Asn1Encodable attr = null;

                                    if (attrSet.Count > 0)
                                    {
                                        attr = attrSet[0];

                                        attributes.Add(aOid.Id, attr);
                                    }

                                    if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                                    {
                                        alias = ((DerBmpString)attr).GetString();
                                        keys[alias] = pkcs12Key;
                                    }
                                    else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                                    {
                                        localId = (Asn1OctetString)attr;
                                    }
                                }

                                string name = Encoding.ASCII.GetString(Hex.Encode(localId.GetOctets()));

                                if (alias == null)
                                {
                                    keys[name] = pkcs12Key;
                                }
                                else
                                {
                                    localIds[alias] = name;
                                }
                            }
                            else
                            {
                                Console.WriteLine("extra " + b.BagID);
                                Console.WriteLine("extra " + Asn1Dump.DumpAsString(b));
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("extra " + c[i].ContentType.Id);
                        Console.WriteLine("extra " + Asn1Dump.DumpAsString(c[i].Content));
                    }
                }
            }

            certs = new Hashtable();
            chainCerts = new Hashtable();
            keyCerts = new Hashtable();

			for (int i = 0; i < chain.Count; ++i)
            {
                SafeBag b = (SafeBag)chain[i];
                CertBag cb = new CertBag((Asn1Sequence)b.BagValue);
				byte[] octets = ((Asn1OctetString) cb.CertValue).GetOctets();
				X509Certificate cert = new X509CertificateParser().ReadCertificate(octets);

				//
                // set the attributes
                //
                Hashtable attributes = new Hashtable();
                X509CertificateEntry pkcs12Cert = new X509CertificateEntry(cert, attributes);
                Asn1OctetString localId = null;
                string alias = null;

                if (b.BagAttributes != null)
                {
					foreach (Asn1Sequence sq in b.BagAttributes)
					{
                        DerObjectIdentifier aOid = (DerObjectIdentifier) sq[0];
                        Asn1Set attrSet = (Asn1Set) sq[1];

						if (attrSet.Count > 0)
                        {
                            Asn1Encodable attr = attrSet[0];

                            attributes.Add(aOid.Id, attr);

                            if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                            {
                                alias = ((DerBmpString)attr).GetString();
                            }
                            else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                            {
                                localId = (Asn1OctetString)attr;
                            }
                        }
                    }
                }

				AsymmetricKeyParameter publicKey = cert.GetPublicKey();
				chainCerts[new CertId(publicKey)] = pkcs12Cert;

				if (unmarkedKey)
                {
                    if (keyCerts.Count == 0)
                    {
                        string name = Encoding.ASCII.GetString(
							Hex.Encode(
								new SubjectKeyIdentifier(
									SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey)).GetKeyIdentifier()));

                        keyCerts[name] = pkcs12Cert;

						object temp = keys["unmarked"];
						keys.Remove("unmarked");
						keys[name] = temp;
                    }
                }
                else
                {
                    if (localId != null)
                    {
                        string name = Encoding.ASCII.GetString(
							Hex.Encode(localId.GetOctets()));

                        keyCerts[name] = pkcs12Cert;
                    }

					if (alias != null)
					{
                        certs[alias] = pkcs12Cert;
                    }
                }
            }
        }

		public AsymmetricKeyEntry GetKey(
            string alias)
        {
            if (alias == null)
                throw new ArgumentNullException("alias");

            return (AsymmetricKeyEntry)keys[alias];
        }

        public bool IsCertificateEntry(
            string alias)
        {
            if (alias == null)
                throw new ArgumentNullException("alias");

            return (certs[alias] != null && keys[alias] == null);
        }

        public bool IsKeyEntry(
            string alias)
        {
            if (alias == null)
                throw new ArgumentNullException("alias");

            return (keys[alias] != null);
        }

		private Hashtable GetAliasesTable()
		{
            Hashtable tab = new Hashtable();

			foreach (string key in certs.Keys)
			{
                tab[key] = "cert";
            }

			foreach (string a in keys.Keys)
			{
				if (tab[a] == null)
				{
                    tab[a] = "key";
                }
            }

			return tab;
		}

		public IEnumerable Aliases
        {
			get { return new EnumerableProxy(GetAliasesTable().Keys); }
        }

		public bool ContainsAlias(
			string alias)
		{
			return certs[alias] != null || keys[alias] != null;
		}

        /**
         * simply return the cert entry for the private key
         */
        public X509CertificateEntry GetCertificate(
            string alias)
        {
            if (alias == null)
                throw new ArgumentNullException("alias");

			X509CertificateEntry c = (X509CertificateEntry) certs[alias];

            //
            // look up the key table - and try the local key id
            //
            if (c == null)
            {
                string id = (string)localIds[alias];
                if (id != null)
                {
                    c = (X509CertificateEntry)keyCerts[id];
                }
                else
                {
                    c = (X509CertificateEntry)keyCerts[alias];
                }
            }

            return c;
        }

        public string GetCertificateAlias(
            X509Certificate cert)
        {
        	if (cert == null)
        		throw new ArgumentNullException("cert");

        	foreach (DictionaryEntry entry in certs)
        	{
				X509CertificateEntry entryValue = (X509CertificateEntry) entry.Value;
        		if (entryValue.Certificate.Equals(cert))
        		{
        			return (string) entry.Key;
				}
            }

			foreach (DictionaryEntry entry in keyCerts)
			{
				X509CertificateEntry entryValue = (X509CertificateEntry) entry.Value;
				if (entryValue.Certificate.Equals(cert))
				{
					return (string) entry.Key;
				}
			}

			return null;
        }

        public X509CertificateEntry[] GetCertificateChain(
            string alias)
        {
            if (alias == null)
                throw new ArgumentNullException("alias");

			if (!IsKeyEntry(alias))
			{
				return null;
			}

			X509CertificateEntry c = GetCertificate(alias);

			if (c != null)
            {
                ArrayList cs = new ArrayList();

                while (c != null)
                {
                    X509Certificate x509c = c.Certificate;
                    X509CertificateEntry nextC = null;

					Asn1OctetString ext = x509c.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
                    if (ext != null)
                    {
						AuthorityKeyIdentifier id = AuthorityKeyIdentifier.GetInstance(
							Asn1Object.FromByteArray(ext.GetOctets()));

						if (id.GetKeyIdentifier() != null)
                        {
                            nextC = (X509CertificateEntry) chainCerts[new CertId(id.GetKeyIdentifier())];
                        }
                    }

                    if (nextC == null)
                    {
                        //
                        // no authority key id, try the Issuer DN
                        //
                        X509Name i = x509c.IssuerDN;
                        X509Name s = x509c.SubjectDN;

                        if (!i.Equivalent(s))
                        {
							foreach (CertId certId in chainCerts.Keys)
							{
								X509CertificateEntry x509CertEntry = (X509CertificateEntry) chainCerts[certId];

								X509Certificate crt = x509CertEntry.Certificate;

								X509Name sub = crt.SubjectDN;
                                if (sub.Equivalent(i))
                                {
									try
									{
										x509c.Verify(crt.GetPublicKey());

										nextC = x509CertEntry;
										break;
									}
									catch (InvalidKeyException)
									{
										// TODO What if it doesn't verify?
									}
                                }
                            }
                        }
                    }

					cs.Add(c);
                    if (nextC != c)     // self signed - end of the chain
                    {
                        c = nextC;
                    }
                    else
                    {
                        c = null;
                    }
                }

				return (X509CertificateEntry[]) cs.ToArray(typeof(X509CertificateEntry));
			}

            return null;
        }

        public void SetCertificateEntry(
            string               alias,
            X509CertificateEntry certEntry)
        {
        	if (alias == null)
        		throw new ArgumentNullException("alias");
        	if (certEntry == null)
        		throw new ArgumentNullException("certEntry");
            if (certs[alias] != null)
                throw new ArgumentException("There is already a certificate with the name " + alias + ".");

            certs[alias] = certEntry;
            chainCerts[new CertId(certEntry.Certificate.GetPublicKey())] = certEntry;
        }

		public void SetKeyEntry(
            string                   alias,
            AsymmetricKeyEntry       keyEntry,
            X509CertificateEntry[]   chain)
        {
        	if (alias == null)
        		throw new ArgumentNullException("alias");
        	if (keyEntry == null)
        		throw new ArgumentNullException("keyEntry");
            if (keyEntry.Key.IsPrivate && (chain == null))
                throw new ArgumentException("No certificate chain for private key");
            if (keys[alias] != null && !keyEntry.Key.Equals(((AsymmetricKeyEntry) keys[alias]).Key))
                throw new ArgumentException("There is already a key with the name " + alias + ".");

            keys[alias] = keyEntry;
            certs[alias] = chain[0];

            for (int i = 0; i != chain.Length; i++)
            {
                chainCerts[new CertId(chain[i].Certificate.GetPublicKey())] = chain[i];
            }
        }

        public void DeleteEntry(
            string  alias)
        {
        	if (alias == null)
        		throw new ArgumentNullException("alias");

            AsymmetricKeyEntry k = (AsymmetricKeyEntry)keys[alias];
            if (k != null)
            {
                keys.Remove(alias);
            }

            X509CertificateEntry c = (X509CertificateEntry)certs[alias];

            if (c != null)
            {
                certs.Remove(alias);
                chainCerts.Remove(new CertId(c.Certificate.GetPublicKey()));
            }

            if (k != null)
            {
                string  id = (string)localIds[alias];
                if (id != null)
                {
                    localIds.Remove(alias);
                    c = (X509CertificateEntry)keyCerts[id];
                }
                if (c != null)
                {
                    keyCerts.Remove(id);
                    chainCerts.Remove(new CertId(c.Certificate.GetPublicKey()));
                }
            }

            if (c == null && k == null)
            {
                throw new ArgumentException("no such entry as " + alias);
            }
        }

		[Obsolete("Use 'Count' property instead")]
		public int Size()
		{
			return Count;
		}

		public int Count
		{
			// TODO Seems a little inefficient
			get { return GetAliasesTable().Count; }
		}

		public void Save(
        	Stream			stream,
        	char[]			password,
        	SecureRandom	random)
        {
        	if (stream == null)
        		throw new ArgumentNullException("stream");
            if (password == null)
                throw new ArgumentNullException("password");
            if (random == null)
                throw new ArgumentNullException("random");

            ContentInfo[] c = new ContentInfo[2];

            //
            // handle the key
            //
            Asn1EncodableVector keyS = new Asn1EncodableVector();
            foreach (string name in keys.Keys)
            {
                byte[] kSalt = new byte[saltSize];
                random.NextBytes(kSalt);

                AsymmetricKeyEntry privKey = (AsymmetricKeyEntry) keys[name];
                EncryptedPrivateKeyInfo kInfo =
					EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
						keyAlgorithm, password, kSalt, minIterations, privKey.Key);

				Asn1EncodableVector kName = new Asn1EncodableVector();

				foreach (string oid in privKey.BagAttributeKeys)
				{
                    kName.Add(
						new DerSequence(
							new DerObjectIdentifier(oid),
							new DerSet(privKey[oid])));
                }

				//
                // make sure we have a local key-id
                //
                if (privKey[PkcsObjectIdentifiers.Pkcs9AtLocalKeyID] == null)
                {
                    X509CertificateEntry ct = GetCertificate(name);

					SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
						ct.Certificate.GetPublicKey());

					kName.Add(
						new DerSequence(
							PkcsObjectIdentifiers.Pkcs9AtLocalKeyID,
							new DerSet(new SubjectKeyIdentifier(info))));
                }

				//
                // make sure we are using the local alias on store
                //
                DerBmpString nm = (DerBmpString) privKey[PkcsObjectIdentifiers.Pkcs9AtFriendlyName];
                if (nm == null || !nm.GetString().Equals(name))
                {
                    kName.Add(
						new DerSequence(
							PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
							new DerSet(new DerBmpString(name))));
                }

                SafeBag kBag = new SafeBag(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag, kInfo.ToAsn1Object(), new DerSet(kName));
                keyS.Add(kBag);
            }

			byte[] derEncodedBytes = new DerSequence(keyS).GetDerEncoded();

            BerOctetString keyString = new BerOctetString(derEncodedBytes);

            //
            // certificate processing
            //
            byte[] cSalt = new byte[saltSize];

            random.NextBytes(cSalt);

            Asn1EncodableVector	certSeq = new Asn1EncodableVector();
            Pkcs12PbeParams		cParams = new Pkcs12PbeParams(cSalt, minIterations);
            AlgorithmIdentifier	cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.ToAsn1Object());
            Hashtable			doneCerts = new Hashtable();

			foreach (string name in keys.Keys)
			{
                X509CertificateEntry certEntry = GetCertificate(name);
                CertBag cBag = new CertBag(
                    PkcsObjectIdentifiers.X509CertType,
                    new DerOctetString(certEntry.Certificate.GetEncoded()));

				Asn1EncodableVector fName = new Asn1EncodableVector();

				foreach (string oid in certEntry.BagAttributeKeys)
				{
					fName.Add(
						new DerSequence(
							new DerObjectIdentifier(oid),
							new DerSet(certEntry[oid])));
                }

				//
                // make sure we are using the local alias on store
                //
                DerBmpString nm = (DerBmpString)certEntry[PkcsObjectIdentifiers.Pkcs9AtFriendlyName];
                if (nm == null || !nm.GetString().Equals(name))
                {
                    fName.Add(
						new DerSequence(
							PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
							new DerSet(new DerBmpString(name))));
                }

                //
                // make sure we have a local key-id
                //
                if (certEntry[PkcsObjectIdentifiers.Pkcs9AtLocalKeyID] == null)
                {
					SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
						certEntry.Certificate.GetPublicKey());

					fName.Add(
						new DerSequence(
							PkcsObjectIdentifiers.Pkcs9AtLocalKeyID,
							new DerSet(new SubjectKeyIdentifier(info))));
                }

				SafeBag sBag = new SafeBag(
					PkcsObjectIdentifiers.CertBag, cBag.ToAsn1Object(), new DerSet(fName));

                certSeq.Add(sBag);

                doneCerts.Add(certEntry.Certificate, certEntry.Certificate);
            }

			foreach (string certId in certs.Keys)
			{
                X509CertificateEntry cert = (X509CertificateEntry)certs[certId];

                if (keys[certId] != null)
                {
                    continue;
                }

                CertBag cBag = new CertBag(
					PkcsObjectIdentifiers.X509CertType,
					new DerOctetString(cert.Certificate.GetEncoded()));

				Asn1EncodableVector fName = new Asn1EncodableVector();

				foreach (string oid in cert.BagAttributeKeys)
				{
					fName.Add(
						new DerSequence(
							new DerObjectIdentifier(oid),
							new DerSet(cert[oid])));
                }

				//
                // make sure we are using the local alias on store
                //
                DerBmpString nm = (DerBmpString) cert[PkcsObjectIdentifiers.Pkcs9AtFriendlyName];
                if (nm == null || !nm.GetString().Equals(certId))
                {
                    fName.Add(
						new DerSequence(
							PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
							new DerSet(new DerBmpString(certId))));
                }

				SafeBag sBag = new SafeBag(PkcsObjectIdentifiers.CertBag,
					cBag.ToAsn1Object(), new DerSet(fName));

				certSeq.Add(sBag);

				doneCerts.Add(cert, cert);
            }

			foreach (CertId certId in chainCerts.Keys)
			{
                X509CertificateEntry cert = (X509CertificateEntry)chainCerts[certId];

                if (doneCerts[cert] != null)
                {
                    continue;
                }

                CertBag cBag = new CertBag(
					PkcsObjectIdentifiers.X509CertType,
					new DerOctetString(cert.Certificate.GetEncoded()));

				Asn1EncodableVector fName = new Asn1EncodableVector();

				foreach (string oid in cert.BagAttributeKeys)
				{
					fName.Add(new DerSequence(new DerObjectIdentifier(oid), new DerSet(cert[oid])));
                }

				SafeBag sBag = new SafeBag(PkcsObjectIdentifiers.CertBag, cBag.ToAsn1Object(), new DerSet(fName));

				certSeq.Add(sBag);
            }

			derEncodedBytes = new DerSequence(certSeq).GetDerEncoded();

			byte[] certBytes = EncryptData(new AlgorithmIdentifier(certAlgorithm, cParams), derEncodedBytes, password);
            EncryptedData cInfo = new EncryptedData(PkcsObjectIdentifiers.Data, cAlgId, new BerOctetString(certBytes));

			c[0] = new ContentInfo(PkcsObjectIdentifiers.Data, keyString);
			c[1] = new ContentInfo(PkcsObjectIdentifiers.EncryptedData, cInfo.ToAsn1Object());

            AuthenticatedSafe auth = new AuthenticatedSafe(c);

			byte[] pkg = auth.GetEncoded();

			ContentInfo mainInfo = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(pkg));

			//
            // create the mac
            //
            byte[] mSalt = new byte[20];
            int itCount = minIterations;

			random.NextBytes(mSalt);

			byte[] data = ((Asn1OctetString)mainInfo.Content).GetOctets();

			MacData mData = null;

			Asn1Encodable parameters = PbeUtilities.GenerateAlgorithmParameters(OiwObjectIdentifiers.IdSha1, mSalt, itCount);
            ICipherParameters keyParameters = PbeUtilities.GenerateCipherParameters(
				OiwObjectIdentifiers.IdSha1, password, parameters);
            IMac mac = (IMac)PbeUtilities.CreateEngine(OiwObjectIdentifiers.IdSha1);

            mac.Init(keyParameters);

            mac.BlockUpdate(data, 0, data.Length);

            byte[] res = new byte[mac.GetMacSize()];

            mac.DoFinal(res, 0);

            AlgorithmIdentifier algId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            DigestInfo dInfo = new DigestInfo(algId, res);

            mData = new MacData(dInfo, mSalt, itCount);

			//
            // output the Pfx
            //
            Pfx pfx = new Pfx(mainInfo, mData);

			BerOutputStream berOut = new BerOutputStream(stream);

			berOut.WriteObject(pfx);
        }
    }
}
