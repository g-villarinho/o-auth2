import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import { SubmissionButton } from "./submission-button";

describe("SubmissionButton", () => {
  describe("Basic rendering", () => {
    it("should render button with text content", () => {
      render(<SubmissionButton>Click here</SubmissionButton>);

      expect(screen.getByRole("button")).toBeInTheDocument();
      expect(screen.getByText("Click here")).toBeInTheDocument();
    });

    it("should render with custom className", () => {
      render(
        <SubmissionButton className="custom-class">Button</SubmissionButton>
      );

      const button = screen.getByRole("button");
      expect(button).toHaveClass("custom-class");
    });

    it("should add data-slot attribute", () => {
      render(<SubmissionButton>Button</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("data-slot", "button");
    });
  });

  describe("Loading states", () => {
    it("should show spinner when loading is true", () => {
      render(<SubmissionButton loading>Submit</SubmissionButton>);

      const button = screen.getByRole("button");
      const spinner = button.querySelector("svg");
      expect(spinner).toBeInTheDocument();
    });

    it("should hide content when loading is true", () => {
      render(<SubmissionButton loading>Submit</SubmissionButton>);

      const content = screen.getByText("Submit");
      expect(content).toHaveClass("opacity-0");
    });

    it("should show content when loading is false", () => {
      render(<SubmissionButton loading={false}>Submit</SubmissionButton>);

      const content = screen.getByText("Submit");
      expect(content).not.toHaveClass("opacity-0");
    });

    it("should disable button when loading is true", () => {
      render(<SubmissionButton loading>Submit</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toBeDisabled();
    });
  });

  describe("Variants", () => {
    it("should apply default variant by default", () => {
      render(<SubmissionButton>Button</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("bg-primary", "text-primary-foreground");
    });

    it("should apply destructive variant correctly", () => {
      render(<SubmissionButton variant="destructive">Delete</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("bg-destructive", "text-white");
    });

    it("should apply outline variant correctly", () => {
      render(<SubmissionButton variant="outline">Cancel</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("border", "bg-transparent");
    });

    it("should apply secondary variant correctly", () => {
      render(
        <SubmissionButton variant="secondary">Secondary</SubmissionButton>
      );

      const button = screen.getByRole("button");
      expect(button).toHaveClass("bg-secondary", "text-secondary-foreground");
    });

    it("should apply ghost variant correctly", () => {
      render(<SubmissionButton variant="ghost">Ghost</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("hover:bg-accent");
    });

    it("should apply link variant correctly", () => {
      render(<SubmissionButton variant="link">Link</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("text-primary", "underline-offset-4");
    });
  });

  describe("Sizes", () => {
    it("should apply default size by default", () => {
      render(<SubmissionButton>Button</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("h-9", "px-4", "py-2");
    });

    it("should apply small size correctly", () => {
      render(<SubmissionButton size="sm">Small</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("h-8", "px-3");
    });

    it("should apply large size correctly", () => {
      render(<SubmissionButton size="lg">Large</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("h-10", "px-6");
    });

    it("should apply icon size correctly", () => {
      render(<SubmissionButton size="icon">🔥</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveClass("size-9");
    });
  });

  describe("Interactions", () => {
    it("should call onClick when clicked", () => {
      const handleClick = jest.fn();
      render(
        <SubmissionButton onClick={handleClick}>Click me</SubmissionButton>
      );

      const button = screen.getByRole("button");
      fireEvent.click(button);

      expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it("should not call onClick when disabled", () => {
      const handleClick = jest.fn();
      render(
        <SubmissionButton onClick={handleClick} disabled>
          Click me
        </SubmissionButton>
      );

      const button = screen.getByRole("button");
      fireEvent.click(button);

      expect(handleClick).not.toHaveBeenCalled();
    });

    it("should not call onClick when loading", () => {
      const handleClick = jest.fn();
      render(
        <SubmissionButton onClick={handleClick} loading>
          Click me
        </SubmissionButton>
      );

      const button = screen.getByRole("button");
      fireEvent.click(button);

      expect(handleClick).not.toHaveBeenCalled();
    });
  });

  describe("HTML properties", () => {
    it("should accept standard HTML attributes", () => {
      render(
        <SubmissionButton
          type="submit"
          id="submit-btn"
          aria-label="Submit form"
        >
          Submit
        </SubmissionButton>
      );

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("type", "submit");
      expect(button).toHaveAttribute("id", "submit-btn");
      expect(button).toHaveAttribute("aria-label", "Submit form");
    });

    it("should be disabled via disabled property", () => {
      render(<SubmissionButton disabled>Disabled</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toBeDisabled();
    });
  });

  describe("Edge cases", () => {
    it("should handle disabled and loading states together", () => {
      render(
        <SubmissionButton disabled loading>
          Button
        </SubmissionButton>
      );

      const button = screen.getByRole("button");
      expect(button).toBeDisabled();
      const spinner = button.querySelector("svg");
      expect(spinner).toBeInTheDocument();
    });

    it("should maintain accessibility during loading", () => {
      render(<SubmissionButton loading>Loading</SubmissionButton>);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("disabled");
    });
  });

  describe("Animations", () => {
    it("should apply transition classes correctly", () => {
      render(<SubmissionButton loading>Animated</SubmissionButton>);

      const content = screen.getByText("Animated");
      expect(content).toHaveClass(
        "transition-transform",
        "duration-300",
        "ease-in-out"
      );
    });

    it("should apply correct transformations during loading", () => {
      render(<SubmissionButton loading>Content</SubmissionButton>);

      const content = screen.getByText("Content");
      expect(content).toHaveClass("-translate-y-full", "opacity-0");
    });
  });
});
