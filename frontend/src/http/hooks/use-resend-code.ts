import { api } from "@/lib/axios";
import { useMutation } from "@tanstack/react-query";

export function useResendCode() {
  return useMutation({
    mutationFn: async () => {
      await api.post("/auth/code/resend");
    },
  });
}
