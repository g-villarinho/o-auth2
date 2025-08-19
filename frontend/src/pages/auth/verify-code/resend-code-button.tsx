import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { useResendCode } from "@/http/hooks/use-resend-code";
import { isAxiosError } from "axios";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";

const INITIAL_COUNTDOWN = 60;
const LOCAL_STORAGE_KEY = "@aetherisid-authx/TE";

interface ResendCodeButtonProps {
  disabled?: boolean;
  className?: string;
}

export function ResendCodeButton({
  disabled = false,
  className,
}: ResendCodeButtonProps) {
  const navigate = useNavigate();
  const [countdown, setCountdown] = useState(0);

  useEffect(() => {
    const cooldownUntil = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (cooldownUntil) {
      const remainingTime = Math.round(
        (parseInt(cooldownUntil) - Date.now()) / 1000
      );

      if (remainingTime > 0) {
        setCountdown(remainingTime);
      } else {
        localStorage.removeItem(LOCAL_STORAGE_KEY);
      }
    }
  }, []);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (countdown > 0) {
      interval = setInterval(() => {
        setCountdown((prev) => prev - 1);
      }, 1000);
    } else {
      localStorage.removeItem(LOCAL_STORAGE_KEY);
    }

    return () => clearInterval(interval);
  }, [countdown]);

  const { mutateAsync: resendCode, isPending: isLoading } = useResendCode();

  function handleRateLimitError(retryAfterHeader: string) {
    const secondsToWait = retryAfterHeader
      ? parseInt(retryAfterHeader, 10)
      : INITIAL_COUNTDOWN;

    const cooldownUntil = Date.now() + secondsToWait * 1000;
    setCountdown(secondsToWait);
    localStorage.setItem(LOCAL_STORAGE_KEY, cooldownUntil.toString());

    toast.error(`Please wait ${secondsToWait}s to resend the code.`);
  }

  async function handleResendCode() {
    if (disabled || isLoading || countdown > 0) return;

    await resendCode(undefined, {
      onSuccess: () => {
        const cooldownUntil = Date.now() + INITIAL_COUNTDOWN * 1000;
        setCountdown(INITIAL_COUNTDOWN);
        localStorage.setItem(LOCAL_STORAGE_KEY, cooldownUntil.toString());
        toast.success("Code sent successfully!");
      },
      onError: (error) => {
        if (isAxiosError(error)) {
          if (error.response?.status === 429) {
            const retryAfterHeader = error.response.headers["retry-after"];
            handleRateLimitError(retryAfterHeader);
            return;
          }

          if (error.response?.status === 401) {
            navigate("/sign-in", { replace: true });
            return;
          }
        }
      },
    });
  }

  const isButtonDisabled = disabled || isLoading || countdown > 0;

  return (
    <div className={cn("flex flex-col items-center gap-2", className)}>
      <Button
        type="button"
        variant="outline"
        size="lg"
        onClick={handleResendCode}
        disabled={isButtonDisabled}
        className="w-full text-white/60 hover:text-white hover:bg-white/10 transition-colors"
      >
        <RefreshCw className={cn("size-4", isLoading && "animate-spin")} />
        {countdown > 0 ? `Resend in ${countdown}s` : "Resend code"}
      </Button>
    </div>
  );
}
