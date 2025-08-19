import { api } from "@/lib/axios";
import { useMutation } from "@tanstack/react-query";

interface LoginRequest {
  email: string;
}

export function useLogin() {
  return useMutation({
    mutationFn: async ({ email }: LoginRequest) => {
      await api.post("/auth/login", { email });
    },
  });
}
