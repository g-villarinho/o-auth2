import { api } from "@/lib/axios";
import { useMutation } from "@tanstack/react-query";

interface AutheticateRequest {
  code: string;
}

export function useAuthenticate() {
  return useMutation({
    mutationFn: async ({ code }: AutheticateRequest) => {
      await api.post("/auth/authenticate", { code });
    },
  });
}
