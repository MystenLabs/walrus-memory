import { getToken } from "next-auth/jwt";
import { getAuthSecret } from "@/lib/auth-secret";
import { isDevelopmentEnvironment } from "@/lib/constants";

export async function getSessionToken(request: Request) {
  try {
    return await getToken({
      req: request,
      secret: getAuthSecret(),
      secureCookie: !isDevelopmentEnvironment,
    });
  } catch (error) {
    // Auth.js URL-decodes Bearer outside its JWT try/catch; malformed % sequences are not a session.
    if (error instanceof URIError) {
      return null;
    }
    throw error;
  }
}
