using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Ocsp
{
	/**
	 * base generator for an OCSP response - at the moment this only supports the
	 * generation of responses containing BasicOCSP responses.
	 */
	public class OCSPRespGenerator
	{
		public static readonly int Successful		= 0;	// Response has valid confirmations
		public static readonly int MalformedRequest	= 1;	// Illegal confirmation request
		public static readonly int InternalError	= 2;	// Internal error in issuer
		public static readonly int TryLater			= 3;	// Try again later
		// (4) is not used
		public static readonly int SigRequired		= 5;	// Must sign the request
		public static readonly int Unauthorized		= 6;	// Request unauthorized

		public OcspResp Generate(
			int     status,
			object  response)
		{
			if (response == null)
			{
				return new OcspResp(new OcspResponse(new OcspResponseStatus(status),null));
			}
			if (response is BasicOcspResp)
			{
				BasicOcspResp r = (BasicOcspResp)response;
				Asn1OctetString octs;

				try
				{
					octs = new DerOctetString(r.GetEncoded());
				}
				catch (Exception e)
				{
					throw new OcspException("can't encode object.", e);
				}

				ResponseBytes rb = new ResponseBytes(
					OcspObjectIdentifiers.PkixOcspBasic, octs);

				return new OcspResp(new OcspResponse(
					new OcspResponseStatus(status), rb));
			}

			throw new OcspException("unknown response object");
		}
	}
}
