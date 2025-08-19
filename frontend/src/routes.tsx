import { createBrowserRouter } from "react-router-dom";

// Layouts
import { AuthLayout } from "@/pages/auth/layout";

// Pages
import { SignInPage } from "@/pages/auth/sign-in";
import { SignUpPage } from "@/pages/auth/sign-up";
import { AccountNotFoundPage } from "@/pages/auth/account-not-found";
import { NotFoundPage } from "@/pages/errors/404";
import { VerifyCodePage } from "./pages/auth/verify-code";
import { OauthDemoPage } from "./pages/auth/oauth-demo";
import { OauthCallbackPage } from "./pages/auth/callback";
import { HomePage } from "./pages/app/home";

export const router = createBrowserRouter([
  {
    element: <AuthLayout />,
    errorElement: <NotFoundPage />,
    children: [
      {
        path: "/sign-in",
        element: <SignInPage />,
      },
      {
        path: "/oauth-demo",
        element: <OauthDemoPage />,
      },
      {
        path: "/sign-up",
        element: <SignUpPage />,
      },
      {
        path: "/account-not-found",
        element: <AccountNotFoundPage />,
      },
      {
        path: "/verify-code",
        element: <VerifyCodePage />,
      },
      {
        path: "/callback",
        element: <OauthCallbackPage />,
      },
    ],
  },

  {
    path: "/",
    errorElement: <NotFoundPage />,
    element: <HomePage />,
  },
]);
