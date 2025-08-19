import { useSearchParams } from "react-router-dom";

export function useQueryState(
  key: string
): [string | null, (value: string) => void] {
  const [searchParams, setSearchParams] = useSearchParams();
  const value = searchParams.get(key);

  function setValue(newValue: string) {
    const newParams = new URLSearchParams(searchParams);
    newParams.set(key, newValue);
    setSearchParams(newParams);
  }

  return [value, setValue];
}
