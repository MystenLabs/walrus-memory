import { useEffect, useId, useRef, useState } from 'react'
import { Check, ChevronDown } from 'lucide-react'

const choices = ['2', '5', '10', '20']

export function RateMultiplierSelect({
  value,
  disabled,
  onChange,
}: {
  value: string
  disabled: boolean
  onChange: (value: string) => void
}) {
  const id = useId()
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const menu = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [focused, setFocused] = useState(Math.max(0, choices.indexOf(value)))
  useEffect(() => {
    if (!open) return
    const close = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', close)
    return () => document.removeEventListener('pointerdown', close)
  }, [open])
  useEffect(() => {
    if (open) {
      const option = menu.current
        ?.querySelectorAll<HTMLButtonElement>('[role="option"]')
        .item(focused)
      option?.focus()
    }
  }, [open, focused])
  const show = () => {
    setFocused(Math.max(0, choices.indexOf(value)))
    setOpen(true)
  }
  const choose = (next: string) => {
    if (next !== value) onChange(next)
    setOpen(false)
    trigger.current?.focus()
  }
  return (
    <div
      className="admin-priority-dropdown"
      ref={root}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null))
          setOpen(false)
      }}
    >
      <button
        ref={trigger}
        type="button"
        role="combobox"
        aria-label="Rate multiplier"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={id}
        className="dashboard-add-key-input admin-priority-select"
        disabled={disabled}
        onClick={() => (open ? setOpen(false) : show())}
        onKeyDown={(event) => {
          if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(event.key)) {
            event.preventDefault()
            show()
          }
          if (event.key === 'Escape') setOpen(false)
        }}
      >
        <span>{choices.includes(value) ? `×${value}` : 'Custom'}</span>
        <ChevronDown
          size={16}
          aria-hidden="true"
          className={open ? 'admin-priority-chevron--open' : ''}
        />
      </button>
      {open && (
        <div
          ref={menu}
          id={id}
          role="listbox"
          aria-label="Rate multiplier options"
          className="admin-priority-menu"
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault()
              setFocused((index) => (index + 1) % choices.length)
            }
            if (event.key === 'ArrowUp') {
              event.preventDefault()
              setFocused(
                (index) => (index + choices.length - 1) % choices.length,
              )
            }
            if (event.key === 'Home') {
              event.preventDefault()
              setFocused(0)
            }
            if (event.key === 'End') {
              event.preventDefault()
              setFocused(choices.length - 1)
            }
            if (event.key === 'Escape') {
              event.preventDefault()
              event.stopPropagation()
              setOpen(false)
              trigger.current?.focus()
            }
            if (event.key === 'Tab') {
              setOpen(false)
              trigger.current?.focus()
            }
          }}
        >
          {choices.map((choice) => (
            <button
              key={choice}
              type="button"
              role="option"
              aria-selected={value === choice}
              tabIndex={-1}
              className="admin-priority-option"
              onClick={() => choose(choice)}
            >
              <span>×{choice}</span>
              {value === choice && <Check size={15} aria-hidden="true" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
