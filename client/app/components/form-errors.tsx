interface FormErrorsProps {
  errors?: string[];
}

export const FormErrors = ({ errors }: FormErrorsProps) => {
  if (!errors || errors.length === 0) {
    return null;
  }

  return (
    <div
      id="form-error"
      aria-live="polite"
      className="mt-2 text-s text-red-500"
    >
      {errors.map((error: string) => (
        <p
          key={error}
          className="flex items-center font-medium p-1"
        >
          {error}
        </p>
      ))}
    </div>
  );
};
