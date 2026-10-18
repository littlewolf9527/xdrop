import {
  expect, it
} from 'vitest'
import {
  mount
} from '@vue/test-utils'
import {
  ElInput
} from 'element-plus'
import {
  readFileSync
} from 'node:fs'
import {
  cwd
} from 'node:process'
const elementInputCss = readFileSync(cwd() + '/node_modules/element-plus/theme-chalk/el-input.css', 'utf8')
const tokens = readFileSync(cwd() + '/src/tokens.css', 'utf8')
const pageCss = readFileSync(cwd() + '/src/style.css', 'utf8')

it('V-r4 login inputs have one frame in both themes', () => {
  const stylesheet = document.createElement('style')
  stylesheet.textContent = elementInputCss + '\n' + tokens
  const pageStyles = document.createElement('style')
  pageStyles.textContent = pageCss
  document.head.append(stylesheet, pageStyles)
  const host = document.createElement('form')
  host.className = 'login'
  document.body.append(host)
  const inputs = [mount(ElInput, {
    attachTo: host
  }), mount(ElInput, {
    attachTo: host, props: {
      type: 'password'
    }
  })]
  try {
    for (const theme of ['light', 'dark']) {
      document.documentElement.dataset.theme = theme
      for (const wrapper of inputs) {
        const input = wrapper.get('input.el-input__inner').element
        // Preserve author declarations even when jsdom drops var() border shorthands.
        let matchedRules = 0
        for (const match of pageCss.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
          const selector = match[1]!.trim()
          let matches = false
          try {
            matches = input.matches(selector)
          } catch {
            /* at-rules are not selectors */
          }
          if (!matches) continue
          matchedRules++
          for (const declaration of match[2]!.split(';')) {
            const [property, ...parts] = declaration.split(':')
            if (/^border(?:-(?:top|right|bottom|left))?(?:-width)?$/.test(property!.trim())) {
              expect(parts.join(':').trim(), selector + ' ' + property).toMatch(/^(?:none|0(?:[a-z%]+)?)(?:\s|$)/)

            }

          }

        }
        expect(matchedRules).toBeGreaterThan(0)
        const style = getComputedStyle(input)
        const rules = [...(pageStyles.sheet?.cssRules || [])]
        for (const rule of rules) {
          const candidate = rule as CSSStyleRule
          if (candidate.selectorText && input.matches(candidate.selectorText)) {
            // CSSOM also catches variable-valued shorthands that jsdom cannot resolve.
            expect(candidate.style.getPropertyValue('border')).not.toMatch(/^[1-9][0-9.]*px/)
            for (const side of ['top', 'right', 'bottom', 'left']) expect(candidate.style.getPropertyValue('border-' + side +
              '-width')).not.toMatch(/^[1-9][0-9.]*px/)

          }

        }
        for (const side of ['Top', 'Right', 'Bottom', 'Left']) {
          expect(style.getPropertyValue('border-' + side.toLowerCase() + '-width'), theme + ' ' + side).toBe('0px')

        }
        expect(input.parentElement?.classList.contains('el-input__wrapper')).toBe(true)

      }

    }

  } finally {
    inputs.forEach(input => input.unmount())
    stylesheet.remove();
    pageStyles.remove();
    host.remove();
    delete document.documentElement.dataset.theme

  }
})
