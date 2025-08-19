import { Outlet } from "react-router-dom";

export function AuthLayout() {
  return (
    <main className="w-full min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md">
        <Outlet />
      </div>
    </main>
  );
}
