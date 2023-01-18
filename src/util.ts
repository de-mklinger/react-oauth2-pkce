export const toSnakeCase = (str: string): string => str
    .split(/(?=[A-Z])/)
    .join("_")
    .toLowerCase();

export const toUrlEncoded = (
  obj: Record<string, string | undefined>
): string => Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .map(
      (k) =>
        encodeURIComponent(toSnakeCase(k)) +
        "=" +
        encodeURIComponent(obj[k]!)
    )
    .join("&");
