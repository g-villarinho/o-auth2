import { api } from "@/lib/axios";
import { useMutation } from "@tanstack/react-query";

export interface RegisterRequest {
  firstName: string;
  lastName: string;
  email: string;
}

export function useRegister() {
  return useMutation({
    mutationFn: async ({ firstName, lastName, email }: RegisterRequest) => {
      await api.post("/auth/register", {
        first_name: firstName,
        last_name: lastName,
        email,
      });
    },
  });
}
