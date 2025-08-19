import { Input } from "@/components/ui/input";
import {
  Form,
  FormField,
  FormItem,
  FormControl,
  FormMessage,
} from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";

import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { useLogin } from "@/http/hooks";
import { useNavigate } from "react-router-dom";
import { isAxiosError } from "axios";
import { useQueryState } from "@/hooks/use-query-state";
import { SubmissionButton } from "@/components/submission-button";

const accountNotFoundSchema = z.object({
  email: z.email("Invalid email address."),
});

type AccountNotFoundFormValues = z.infer<typeof accountNotFoundSchema>;

interface AccountNotFoundFormProps {
  continueUrl: string;
}

export function AccountNotFoundForm({ continueUrl }: AccountNotFoundFormProps) {
  const navigate = useNavigate();
  const [, setEmail] = useQueryState("email");

  const form = useForm<AccountNotFoundFormValues>({
    resolver: zodResolver(accountNotFoundSchema),
    defaultValues: {
      email: "",
    },
  });

  const { mutateAsync: login, isPending } = useLogin();

  async function handleTryAgain({ email }: AccountNotFoundFormValues) {
    await login(
      { email },
      {
        onSuccess: () => {
          setEmail(email);
          navigate(`/verify-code?continue=${encodeURIComponent(continueUrl)}`);
        },
        onError: (error) => {
          if (isAxiosError(error)) {
            if (error.response?.status === 404) {
              setEmail(email);
              form.reset();
            }
          }
        },
      }
    );
  }

  function handleCreateAccount() {
    navigate(`/sign-up?continue=${encodeURIComponent(continueUrl)}`);
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleTryAgain)} className="space-y-4">
        <FormField
          name="email"
          control={form.control}
          render={({ field }) => (
            <FormItem>
              <FormControl>
                <div className="flex flex-col gap-2">
                  <Label htmlFor="email">E-mail</Label>
                  <Input
                    className="peer"
                    type="email"
                    autoFocus
                    disabled={isPending}
                    placeholder="Digite seu e-mail"
                    {...field}
                  />
                </div>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="flex gap-3">
          <SubmissionButton
            type="submit"
            className="flex-1 group relative overflow-hidden"
            size="lg"
            loading={isPending}
          >
            <span className="flex items-center justify-center gap-2">
              Tentar novamente
            </span>
          </SubmissionButton>
          <Button
            type="button"
            variant="outline"
            className="flex-1 group relative overflow-hidden"
            size="lg"
            onClick={handleCreateAccount}
            disabled={isPending}
          >
            <span className="flex items-center justify-center gap-2">
              Criar conta
            </span>
          </Button>
        </div>
      </form>
    </Form>
  );
}
