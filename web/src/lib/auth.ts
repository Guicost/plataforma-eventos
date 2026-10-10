import { SignJWT, jwtVerify } from "jose";

const secret = new TextEncoder().encode(process.env.JWT_SECRET);

export type Role = "ADMIN" | "USER";

export async function signToken(userId: string, role: Role) {
  return new SignJWT({ role })
    .setSubject(userId)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(secret);
}

// Lê o header "Authorization: Bearer <token>" e devolve o usuário logado (ou null)
export async function getAuth(req: Request) {
  const header = req.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;

  try {
    const { payload } = await jwtVerify(header.slice(7), secret);
    if (!payload.sub) return null;
    return { userId: payload.sub, role: payload.role as Role };
  } catch {
    return null;
  }
}