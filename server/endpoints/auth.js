const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const { User } = require("../models/user");
const { validSessionForUser, userFromSession, makeJWT } = require("../utils/http");
const { validatedRequest } = require("../utils/middleware/validatedRequest");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

// RP ID should be the domain of the application
// For local development it is likely "localhost"
const rpName = "AnythingLLM";
const rpID = process.env.RP_ID || "localhost";
const origin = process.env.RP_ORIGIN || `http://${rpID}:3000`;

function authEndpoints(app) {
  if (!app) return;

  app.get("/auth/webauthn/register/challenge", [validatedRequest], async (request, response) => {
    try {
      const user = await userFromSession(request, response);
      if (!user) return response.sendStatus(401).end();

      const userCredentials = await prisma.webauthn_credentials.findMany({
        where: { userId: user.id },
      });

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: String(user.id),
        userName: user.username,
        attestationType: "none",
        excludeCredentials: userCredentials.map((cred) => ({
          id: cred.credentialID,
          transports: cred.transports ? JSON.parse(cred.transports) : undefined,
        })),
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
          authenticatorAttachment: "cross-platform",
        },
      });

      // Save the challenge in the session or a temporary store
      // Since we don't have a session store readily available for arbitrary data,
      // and we want to keep it stateless, we can sign the challenge in a JWT or similar.
      // However, for simplicity in this codebase which uses JWT for sessions,
      // we can't easily append to the user session without re-issuing it.
      // A common pattern is to send the challenge back and have the client sign it,
      // but we need to verify it matches what we sent.
      // We will store it in a temporary cache or just rely on the signed token if we had one.
      // For now, let's use a simple in-memory map for challenges (not scalable but works for single instance)
      // OR better, we can use the `cache_data` table.

      await prisma.cache_data.create({
        data: {
          name: `webauthn_challenge_${user.id}`,
          data: options.challenge,
          expiresAt: new Date(Date.now() + 60000 * 5), // 5 minutes
        }
      });

      response.status(200).json(options);
    } catch (e) {
      console.error(e);
      response.sendStatus(500).end();
    }
  });

  app.post("/auth/webauthn/register/verify", [validatedRequest], async (request, response) => {
    try {
      const user = await userFromSession(request, response);
      if (!user) return response.sendStatus(401).end();

      const { response: attResp } = request.body;

      const challengeRecord = await prisma.cache_data.findFirst({
        where: {
          name: `webauthn_challenge_${user.id}`,
          expiresAt: { gt: new Date() }
        },
        orderBy: { id: 'desc' }
      });

      if (!challengeRecord) {
        return response.status(400).json({ error: "Challenge expired or invalid" });
      }

      const expectedChallenge = challengeRecord.data;

      const verification = await verifyRegistrationResponse({
        response: attResp,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      });

      if (verification.verified && verification.registrationInfo) {
        const { credentialID, credentialPublicKey, counter, credentialBackedUp } = verification.registrationInfo;

        await prisma.webauthn_credentials.create({
          data: {
            userId: user.id,
            credentialID: credentialID,
            publicKey: Buffer.from(credentialPublicKey).toString('base64'),
            counter: BigInt(counter),
            transports: JSON.stringify(attResp.response.transports),
          },
        });

        // Clean up challenge
        await prisma.cache_data.delete({ where: { id: challengeRecord.id } });

        response.status(200).json({ verified: true });
      } else {
        response.status(400).json({ verified: false, error: "Verification failed" });
      }
    } catch (e) {
      console.error(e);
      response.sendStatus(500).end();
    }
  });

  app.post("/auth/webauthn/login/challenge", async (request, response) => {
    try {
      // Login is public, we don't know the user yet unless they provide a username.
      // However, for Passkeys (resident keys), we might not need a username.
      // But standard WebAuthn often starts with a username or uses a resident key flow.
      // Let's support username-based flow first as it matches the current login UI.

      const { username } = request.body;
      let user = null;

      if (username) {
         user = await User.get({ username });
         if (!user) return response.status(400).json({ error: "User not found" });
      }

      // If user is found, get their credentials to allowlist them (optional but good for UX)
      // If using resident keys, we don't strictly need this, but it helps avoiding "use a security key" prompts for non-registered users.

      let userCredentials = [];
      if (user) {
        userCredentials = await prisma.webauthn_credentials.findMany({
          where: { userId: user.id },
        });
      }

      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: userCredentials.map((cred) => ({
          id: cred.credentialID,
          transports: cred.transports ? JSON.parse(cred.transports) : undefined,
        })),
        userVerification: "preferred",
      });

      // Store challenge. Since we might not have a user ID yet (if resident key flow),
      // we need a way to link the challenge verification.
      // We can return a challenge ID to the client and have them send it back.
      // For now, let's just use a random ID.
      const challengeId = Math.random().toString(36).substring(7);

      await prisma.cache_data.create({
        data: {
          name: `webauthn_login_challenge_${challengeId}`,
          data: JSON.stringify({ challenge: options.challenge, userId: user ? user.id : null }),
          expiresAt: new Date(Date.now() + 60000 * 5),
        }
      });

      response.status(200).json({ options, challengeId });
    } catch (e) {
      console.error(e);
      response.sendStatus(500).end();
    }
  });

  app.post("/auth/webauthn/login/verify", async (request, response) => {
    try {
      const { response: authResp, challengeId } = request.body;

      const challengeRecord = await prisma.cache_data.findFirst({
        where: {
          name: `webauthn_login_challenge_${challengeId}`,
          expiresAt: { gt: new Date() }
        },
        orderBy: { id: 'desc' }
      });

      if (!challengeRecord) {
        return response.status(400).json({ error: "Challenge expired or invalid" });
      }

      const { challenge: expectedChallenge, userId } = JSON.parse(challengeRecord.data);

      let credential;
      if (userId) {
          // If we knew the user, find the specific credential
          // Actually, we need to find the credential by ID from the response
          credential = await prisma.webauthn_credentials.findFirst({
            where: { credentialID: authResp.id, userId: userId }
          });
      } else {
          // If resident key flow (not fully implemented yet as we require username),
          // we would search by credentialID globally.
          credential = await prisma.webauthn_credentials.findFirst({
            where: { credentialID: authResp.id }
          });
      }

      if (!credential) {
        return response.status(400).json({ error: "Credential not found" });
      }

      const user = await User.get({ id: credential.userId });
      if (!user) {
          return response.status(400).json({ error: "User not found" });
      }

      const verification = await verifyAuthenticationResponse({
        response: authResp,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: {
          credentialID: credential.credentialID,
          credentialPublicKey: Buffer.from(credential.publicKey, 'base64'),
          counter: Number(credential.counter),
          transports: credential.transports ? JSON.parse(credential.transports) : undefined,
        },
      });

      if (verification.verified) {
        const { authenticationInfo } = verification;
        const { newCounter } = authenticationInfo;

        await prisma.webauthn_credentials.update({
          where: { id: credential.id },
          data: { counter: BigInt(newCounter) },
        });

        // Clean up challenge
        await prisma.cache_data.delete({ where: { id: challengeRecord.id } });

        // Issue JWT
        const token = makeJWT(
          { id: user.id, username: user.username },
          process.env.JWT_EXPIRY || "1d"
        );

        response.status(200).json({ verified: true, token, user: User.filterFields(user) });
      } else {
        response.status(400).json({ verified: false, error: "Verification failed" });
      }
    } catch (e) {
      console.error(e);
      response.sendStatus(500).end();
    }
  });
}

module.exports = { authEndpoints };
