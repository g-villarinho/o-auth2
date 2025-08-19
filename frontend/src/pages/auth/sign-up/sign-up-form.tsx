import { Input } from "@/components/ui/input";
import {
  Form,
  FormField,
  FormItem,
  FormControl,
  FormMessage,
  FormLabel,
} from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useRegister } from "@/http/hooks";
import { useNavigate } from "react-router-dom";
import { isAxiosError } from "axios";
import { SubmissionButton } from "@/components/submission-button";
import { ArrowRight } from "lucide-react";
import { useQueryState } from "@/hooks/use-query-state";

const signUpSchema = z.object({
  firstName: z.string().min(1, "Name is required."),
  lastName: z.string().min(1, "Last name is required."),
  email: z.email("Invalid email address."),
});

type SignUpFormValues = z.infer<typeof signUpSchema>;

interface SignUpFormProps {
  continueUrl: string;
}

export function SignUpForm({ continueUrl }: SignUpFormProps) {
  const [, setEmail] = useQueryState("email");
  const navigate = useNavigate();

  const form = useForm<SignUpFormValues>({
    resolver: zodResolver(signUpSchema),
    defaultValues: {
      firstName: "",
      lastName: "",
      email: "",
    },
  });

  const { mutateAsync: register } = useRegister();

  function handleSubmit({ firstName, lastName, email }: SignUpFormValues) {
    register(
      { firstName, lastName, email },
      {
        onSuccess: () => {
          setEmail(email);
          navigate(`/verify-code?continue=${encodeURIComponent(continueUrl)}`);
        },
        onError: (error) => {
          if (isAxiosError(error)) {
            if (error.response?.status === 409) {
              form.setError("email", {
                message: "This email is not allowed. Please try again.",
              });
            }
          }
        },
      }
    );
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
        <div className="flex gap-2">
          <FormField
            name="firstName"
            control={form.control}
            render={({ field }) => (
              <FormItem className="w-1/2">
                <FormLabel>First name</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            name="lastName"
            control={form.control}
            render={({ field }) => (
              <FormItem className="w-1/2">
                <FormLabel>Last name</FormLabel>
                <FormControl>
                  <Input {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
        <FormField
          name="email"
          control={form.control}
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
              <FormControl>
                <Input type="email" {...field} />
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
            Create an account
            <ArrowRight className="size-4 opacity-0 transition-all duration-300 group-hover:opacity-100 group-hover:translate-x-1" />
          </span>
        </SubmissionButton>
      </form>
    </Form>
  );
}
