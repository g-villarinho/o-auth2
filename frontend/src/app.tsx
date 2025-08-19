import { RouterProvider } from "react-router-dom";
import { HeadProvider } from "react-head";
import { Toaster } from "react-hot-toast";
import { QueryClientProvider } from "@tanstack/react-query";

import { router } from "@/routes";
import { toastOptions } from "@/lib/toast";
import { queryClient } from "@/lib/react-query";
import { AuthProvider } from "@/contexts/auth-context";

export function App() {
  return (
    <HeadProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <Toaster toastOptions={toastOptions} />
          <RouterProvider router={router} />
        </AuthProvider>
      </QueryClientProvider>
    </HeadProvider>
  );
}
