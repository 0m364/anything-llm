import { startRegistration, startAuthentication } from "@simplewebauthn/browser";
import { API_BASE } from "./constants";
import { baseHeaders } from "./request";

export const WebAuthn = {
  register: async () => {
    try {
      // 1. Get options from server
      const resp = await fetch(`${API_BASE}/auth/webauthn/register/challenge`, {
        headers: baseHeaders(),
      });

      if (!resp.ok) throw new Error("Failed to get registration options");
      const options = await resp.json();

      // 2. Start registration
      const attResp = await startRegistration(options);

      // 3. Send response to server
      const verificationResp = await fetch(`${API_BASE}/auth/webauthn/register/verify`, {
        method: "POST",
        headers: {
            ...baseHeaders(),
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ response: attResp }),
      });

      if (!verificationResp.ok) throw new Error("Verification failed");
      const verificationJSON = await verificationResp.json();

      return verificationJSON.verified;
    } catch (e) {
      console.error(e);
      throw e;
    }
  },

  login: async (username) => {
    try {
      // 1. Get options from server
      const resp = await fetch(`${API_BASE}/auth/webauthn/login/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });

      if (!resp.ok) {
        const error = await resp.json();
        throw new Error(error.error || "Failed to get login options");
      }
      const { options, challengeId } = await resp.json();

      // 2. Start authentication
      const authResp = await startAuthentication(options);

      // 3. Send response to server
      const verificationResp = await fetch(`${API_BASE}/auth/webauthn/login/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ response: authResp, challengeId }),
      });

      if (!verificationResp.ok) {
        const error = await verificationResp.json();
        throw new Error(error.error || "Verification failed");
      }
      return await verificationResp.json();
    } catch (e) {
      console.error(e);
      throw e;
    }
  }
};
