export const authResponseParameterNames = [
  "code",
  "state",
  "error",
  "error_description",
  "error_uri",
] as const;

export type AuthResponseParameterName =
  (typeof authResponseParameterNames)[number];

export function isResponseParameterName(
  x: unknown
): x is AuthResponseParameterName {
  return (
    typeof x === "string" &&
    authResponseParameterNames.includes(x as AuthResponseParameterName)
  );
}

export type AuthResponseParameters = {
  [name in AuthResponseParameterName]?: string;
};

export function getAuthResponseParameters(
  searchParams: URLSearchParams
): AuthResponseParameters {
  const authResponseParameters: AuthResponseParameters = {}

  authResponseParameterNames.forEach((name) => {
    authResponseParameters[name] = searchParams.get(name) ?? undefined;
  });

  return authResponseParameters;
}

export type WasDeleted = boolean;

export function deleteAuthResponseParameters(
  searchParams: URLSearchParams
): WasDeleted {
  const foundParameters = authResponseParameterNames.filter((name) =>
    searchParams.has(name)
  );

  foundParameters.forEach((name) => {
    searchParams.delete(name);
  });

  return foundParameters.length > 0;
}
