import { z } from "zod";

export const envSchema = z.object({
  MODE: z.enum(["production", "development", "test"]),
  VITE_API_URL: z.string(),
  VITE_ENABLE_API_DELAY: z.string().transform((value) => value === "true"),
  VITE_OAUTH_CLIENT_ID: z.string(),
  VITE_OAUTH_REDIRECT_URI: z.string(),
  VITE_OAUTH_RESPONSE_TYPE: z.string(),
  VITE_OAUTH_SCOPE: z.string(),
  VITE_OAUTH_AUTORIZE_ENDPOINT: z.string(),
  VITE_OAUTH_EXCHANGE_TOKEN_ENDPOINT: z.string(),
});

export const env = envSchema.parse(import.meta.env);
