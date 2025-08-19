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
import { ArrowRight } from "lucide-react";
import { Label } from "@/components/ui/label";
import { SubmissionButton } from "@/components/submission-button";
import { useNavigate } from "react-router-dom";
import { useQueryState } from "@/hooks/use-query-state";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { useAuthenticate } from "@/http/hooks/use-authenticate";
import { isAxiosError } from "axios";

const verifyCodeSchema = z.object({
  code: z.string().length(6, "Code must be 6 digits"),
});

type VerifyCodeFormValues = z.infer<typeof verifyCodeSchema>;

interface VerifyCodeFormProps {
  continueUrl: string;
}

export function VerifyCodeForm({ continueUrl }: VerifyCodeFormProps) {
  const navigate = useNavigate();
  const [email] = useQueryState("email");

  const form = useForm<VerifyCodeFormValues>({
    resolver: zodResolver(verifyCodeSchema),
    defaultValues: {
      code: "",
    },
  });

  const { mutateAsync: authenticate } = useAuthenticate();

  async function handleVerifyCode({ code }: VerifyCodeFormValues) {
    await authenticate(
      {
        code,
      },
      {
        onSuccess: () => {
          window.location.replace(decodeURIComponent(continueUrl));
        },
        onError: (error) => {
          if (isAxiosError(error)) {
            if (error.response?.status === 400) {
              form.setError("code", {
                message: "Invalid code. Please try again.",
              });
            }

            if (error.response?.status === 401) {
              navigate(`/sign-in?continue=${encodeURIComponent(continueUrl)}`);
            }
          }
        },
      }
    );
  }

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleVerifyCode)}
        className="space-y-6"
      >
        <FormField
          name="code"
          control={form.control}
          render={({ field }) => (
            <FormItem>
              <FormControl>
                <div className="flex flex-col gap-3">
                  <Label
                    htmlFor="code"
                    className="text-white text-sm font-medium"
                  >
                    Verification code
                  </Label>
                  <div className="flex justify-center">
                    <InputOTP
                      maxLength={6}
                      value={field.value}
                      onChange={field.onChange}
                      disabled={form.formState.isSubmitting}
                      className="gap-4"
                    >
                      <InputOTPGroup className="gap-4">
                        <InputOTPSlot
                          index={0}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                        <InputOTPSlot
                          index={1}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                        <InputOTPSlot
                          index={2}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                        <InputOTPSlot
                          index={3}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                        <InputOTPSlot
                          index={4}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                        <InputOTPSlot
                          index={5}
                          className="size-12 text-lg border border-white/20 rounded-lg"
                        />
                      </InputOTPGroup>
                    </InputOTP>
                  </div>
                  <p className="text-white/60 text-xs text-center">
                    Enter the 6-digit code sent to{" "}
                    {email && (
                      <span className="font-medium text-white">{email}</span>
                    )}
                    {!email && (
                      <span className="font-medium text-white">
                        Your email address
                      </span>
                    )}
                  </p>
                </div>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <SubmissionButton
          type="submit"
          className="w-full group relative overflow-hidden"
          size="lg"
          loading={form.formState.isSubmitting}
        >
          <span className="flex items-center justify-center gap-2">
            Verify code
            <ArrowRight className="size-4 opacity-0 transition-all duration-300 group-hover:opacity-100 group-hover:translate-x-1" />
          </span>
        </SubmissionButton>
      </form>
    </Form>
  );
}
