import { CssVarsProvider } from "@mui/joy";
import classNames from "classnames";
import { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Provider } from "react-redux";
import { ANIMATION_DURATION } from "@/helpers/consts";
import store from "@/store";
import { useDialogStore } from "@/store/module";
import theme from "@/theme";
import "@/less/base-dialog.less";

interface DialogConfig {
  dialogName: string;
  className?: string;
  containerClassName?: string;
  clickSpaceDestroy?: boolean;
  //
  isFullscreen?: boolean;
}

interface Props extends DialogConfig, DialogProps {
  children: React.ReactNode;
}

const BaseDialog: React.FC<Props> = (props: Props) => {
  const { children, className, containerClassName, clickSpaceDestroy, dialogName, destroy } = props;
  const dialogStore = useDialogStore();
  const dialogContainerRef = useRef<HTMLDivElement>(null);
  const dialogIndex = dialogStore.state.dialogStack.findIndex((item) => item === dialogName);

  const style: React.CSSProperties | undefined = !props.isFullscreen ? undefined : {
    position: 'fixed',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    borderRadius: 0,
  };

  useEffect(() => {
    dialogStore.pushDialogStack(dialogName);
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.code === "Escape") {
        if (dialogName === dialogStore.topDialogStack()) {
          destroy();
        }
      }
    };

    document.body.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.removeEventListener("keydown", handleKeyDown);
      dialogStore.removeDialog(dialogName);
    };
  }, []);

  useEffect(() => {
    if (dialogIndex > 0 && dialogContainerRef.current) {
      dialogContainerRef.current.style.marginTop = `${dialogIndex * 16}px`;
    }
  }, [dialogIndex]);

  const handleSpaceClicked = () => {
    if (clickSpaceDestroy) {
      destroy();
    }
  };

  return (
    <div className={classNames("dialog-wrapper", className)} onMouseDown={handleSpaceClicked}>
      <div
        ref={dialogContainerRef}
        className={classNames("dialog-container", containerClassName)}
        onMouseDown={(e) => e.stopPropagation()}
        style={style}
      >
        {children}
      </div>
    </div>
  );
};

export function generateDialog<T extends DialogProps>(
  config: DialogConfig,
  DialogComponent: React.FC<T>,
  props?: Omit<T, "destroy" | "hide">,
): DialogCallback {
  const tempDiv = document.createElement("div");
  const dialog = createRoot(tempDiv);
  document.body.append(tempDiv);
  document.body.style.overflow = "hidden";



  setTimeout(() => {
    tempDiv.firstElementChild?.classList.add("showup");
  }, 0);

  const cbs: DialogCallback = {
    destroy: () => {
      tempDiv.firstElementChild?.classList.remove("showup");
      tempDiv.firstElementChild?.classList.add("showoff");
      document.body.style.removeProperty("overflow");
      setTimeout(() => {
        dialog.unmount();
        tempDiv.remove();
      }, ANIMATION_DURATION);
    },
    hide: () => {
      tempDiv.firstElementChild?.classList.remove("showup");
      tempDiv.firstElementChild?.classList.add("showoff");
    },
  };


  const dialogProps = {
    ...props,
    destroy: cbs.destroy,
    hide: cbs.hide,
  } as T;

  const Fragment = (
    <Provider store={store}>
      <CssVarsProvider theme={theme}>
        <XDialog
          DialogComponent={DialogComponent}
          config={config}
          props={dialogProps}
          cbs={cbs}
        />
      </CssVarsProvider>
    </Provider>
  );

  dialog.render(Fragment);

  return cbs;
}

interface XDialogProps<T> {
  DialogComponent: React.FC<T>,
  //
  config: DialogConfig,
  props?: Omit<T, "destroy" | "hide">,
  //
  cbs: DialogCallback,
}

function XDialog<T = any>(props: XDialogProps<T>) {
  const DialogComponent = props.DialogComponent as any;

  const [isFullscreen, setIsFullscreen] = useState(false);

  const onFullscreenToggle = () => {
    setIsFullscreen(!isFullscreen);
  };


  return (
    <BaseDialog
      destroy={props.cbs.destroy}
      hide={props.cbs.hide}
      clickSpaceDestroy={true}
      {...props.config}
      isFullscreen={isFullscreen}
    >
      <DialogComponent
        {...props.props}
        isFullscreen={isFullscreen}
        onFullscreenToggle={onFullscreenToggle}
      />
    </BaseDialog>
  );
}
