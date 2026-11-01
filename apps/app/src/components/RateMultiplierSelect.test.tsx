import { fireEvent, render, screen, cleanup } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { RateMultiplierSelect } from './RateMultiplierSelect'
afterEach(cleanup)
it('shows all choices and the selected check, and closes after selection', () => {
  const onChange = vi.fn()
  render(
    <RateMultiplierSelect value="5" disabled={false} onChange={onChange} />,
  )
  fireEvent.click(screen.getByRole('combobox'))
  expect(screen.getAllByRole('option')).toHaveLength(4)
  expect(screen.getByRole('option', { name: '×5' })).toHaveAttribute(
    'aria-selected',
    'true',
  )
  fireEvent.click(screen.getByRole('option', { name: '×20' }))
  expect(onChange).toHaveBeenCalledWith('20')
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  expect(screen.getByRole('combobox')).toHaveFocus()
})
it('supports keyboard navigation and Escape without changing the value', () => {
  const onChange = vi.fn()
  render(
    <RateMultiplierSelect value="2" disabled={false} onChange={onChange} />,
  )
  fireEvent.keyDown(screen.getByRole('combobox'), { key: 'ArrowDown' })
  expect(screen.getByRole('option', { name: '×2' })).toHaveFocus()
  fireEvent.keyDown(screen.getByRole('option', { name: '×2' }), { key: 'End' })
  expect(screen.getByRole('option', { name: '×20' })).toHaveFocus()
  fireEvent.keyDown(screen.getByRole('option', { name: '×20' }), {
    key: 'Escape',
  })
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  expect(screen.getByRole('combobox')).toHaveFocus()
  expect(onChange).not.toHaveBeenCalled()
})
it('dismisses on an outside click and cannot open while disabled', () => {
  const { rerender } = render(
    <RateMultiplierSelect value="2" disabled={false} onChange={vi.fn()} />,
  )
  fireEvent.click(screen.getByRole('combobox'))
  fireEvent.pointerDown(document.body)
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  rerender(<RateMultiplierSelect value="2" disabled onChange={vi.fn()} />)
  expect(screen.getByRole('combobox')).toBeDisabled()
})
